package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/mihomo/component/preferred"
	icontext "github.com/metacubex/mihomo/context"

	D "github.com/miekg/dns"
)

// withPreferredTestManager installs a prepared manager (no schedulers), runs
// the test with it as Default, and restores the previous manager afterwards.
func withPreferredTestManager(t *testing.T, cfg preferred.EntryConfig, v4Pool, v6Pool []netip.Addr) {
	t.Helper()
	restore := preferred.InstallForTesting(cfg, v4Pool, v6Pool)
	t.Cleanup(restore)
}

// stubUpstream answers A/AAAA queries with the given IPs (original TTL 300).
func stubUpstream(ips []netip.Addr, ttl uint32) handler {
	return func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
		msg := r.Copy()
		q := r.Question[0]
		for _, ip := range ips {
			if q.Qtype == D.TypeA && (ip.Is4() || ip.Is4In6()) {
				msg.Answer = append(msg.Answer, &D.A{
					Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: ttl},
					A:   ip.Unmap().AsSlice(),
				})
			}
			if q.Qtype == D.TypeAAAA && ip.Is6() && !ip.Is4In6() {
				msg.Answer = append(msg.Answer, &D.AAAA{
					Hdr:  D.RR_Header{Name: q.Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: ttl},
					AAAA: ip.AsSlice(),
				})
			}
		}
		msg.SetRcode(r, D.RcodeSuccess)
		return msg, nil
	}
}

func newQuery(name string, qtype uint16) *D.Msg {
	m := &D.Msg{}
	m.SetQuestion(D.Fqdn(name), qtype)
	return m
}

func ipsOf(t *testing.T, msg *D.Msg) []netip.Addr {
	t.Helper()
	return msgToIP(msg)
}

func TestWithPreferredIPRewritesA(t *testing.T) {
	withPreferredTestManager(t, preferred.EntryConfig{
		Name: "cf",
		CIDR: []string{"103.21.244.0/22"},
	}, []netip.Addr{
		netip.MustParseAddr("104.16.1.1"),
		netip.MustParseAddr("104.16.2.2"),
	}, nil)

	h := withPreferredIP(stubUpstream([]netip.Addr{
		netip.MustParseAddr("103.21.244.7"), // in range
		netip.MustParseAddr("8.8.8.8"),      // not in range, whole-family rewrite drops it
	}, 300))

	resp, err := h(icontext.NewDNSContext(context.Background()), newQuery("tracker.example.com", D.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	got := ipsOf(t, resp)
	if len(got) != 2 || got[0] != netip.MustParseAddr("104.16.1.1") {
		t.Fatalf("expected rewritten pool, got %v", got)
	}
	if ttl := resp.Answer[0].Header().Ttl; ttl != 60 {
		t.Fatalf("expected TTL capped to 60, got %d", ttl)
	}
}

func TestWithPreferredIPPassthroughWhenNoMatch(t *testing.T) {
	withPreferredTestManager(t, preferred.EntryConfig{
		Name: "cf",
		CIDR: []string{"103.21.244.0/22"},
	}, []netip.Addr{netip.MustParseAddr("104.16.1.1")}, nil)

	orig := netip.MustParseAddr("8.8.8.8")
	h := withPreferredIP(stubUpstream([]netip.Addr{orig}, 300))
	resp, err := h(icontext.NewDNSContext(context.Background()), newQuery("dns.google", D.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if got := ipsOf(t, resp); len(got) != 1 || got[0] != orig {
		t.Fatalf("non-matched answer must pass through unchanged, got %v", got)
	}
}

func TestWithPreferredIPBlocksAAAA(t *testing.T) {
	withPreferredTestManager(t, preferred.EntryConfig{
		Name: "cf",
		CIDR: []string{"103.21.244.0/22", "2606:4700::/32"},
		IPv6: preferred.ModeBlock,
	}, nil, nil)

	h := withPreferredIP(stubUpstream([]netip.Addr{netip.MustParseAddr("2606:4700::64")}, 300))
	resp, err := h(icontext.NewDNSContext(context.Background()), newQuery("tracker.example.com", D.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("ipv6=block must return empty answer, got %v", resp.Answer)
	}
	if resp.Rcode != D.RcodeSuccess {
		t.Fatalf("block must be NOERROR/empty, got rcode %d", resp.Rcode)
	}
}

func TestWithPreferredIPReplacesAAAAWhenReplace(t *testing.T) {
	withPreferredTestManager(t, preferred.EntryConfig{
		Name: "cf",
		CIDR: []string{"103.21.244.0/22", "2606:4700::/32"},
	}, nil, []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")})

	h := withPreferredIP(stubUpstream([]netip.Addr{netip.MustParseAddr("2606:4700::64")}, 300))
	resp, err := h(icontext.NewDNSContext(context.Background()), newQuery("tracker.example.com", D.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	if got := ipsOf(t, resp); len(got) != 1 || got[0] != netip.MustParseAddr("2606:4700:4700::1111") {
		t.Fatalf("expected rewritten v6 pool, got %v", got)
	}
}

func TestWithPreferredIPPassthroughWhenPoolEmpty(t *testing.T) {
	withPreferredTestManager(t, preferred.EntryConfig{
		Name: "cf",
		CIDR: []string{"103.21.244.0/22"},
	}, nil, nil) // pools empty: first test pending

	orig := netip.MustParseAddr("103.21.244.7")
	h := withPreferredIP(stubUpstream([]netip.Addr{orig}, 300))
	resp, err := h(icontext.NewDNSContext(context.Background()), newQuery("tracker.example.com", D.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if got := ipsOf(t, resp); len(got) != 1 || got[0] != orig {
		t.Fatalf("pool-not-ready must passthrough original answer, got %v", got)
	}
}

func TestWithPreferredIPMappingRecordsRewrittenIP(t *testing.T) {
	// ADR-0001 core invariant: withMapping must see the REWRITTEN IP so TUN
	// DIRECT connections keep matching DOMAIN rules.
	withPreferredTestManager(t, preferred.EntryConfig{
		Name: "cf",
		CIDR: []string{"103.21.244.0/22"},
	}, []netip.Addr{netip.MustParseAddr("104.16.1.1")}, nil)

	mapping := lru.New(lru.WithSize[netip.Addr, string](64))
	mw := compose([]middleware{withMapping(mapping)}, withPreferredIP(stubUpstream([]netip.Addr{netip.MustParseAddr("103.21.244.7")}, 300)))

	resp, err := mw(icontext.NewDNSContext(context.Background()), newQuery("tracker.example.com", D.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if got := ipsOf(t, resp); len(got) != 1 || got[0] != netip.MustParseAddr("104.16.1.1") {
		t.Fatalf("rewrite must happen inside mapping middleware, got %v", got)
	}
	if host, ok := mapping.Get(netip.MustParseAddr("104.16.1.1")); !ok || host != "tracker.example.com" {
		t.Fatalf("mapping must record the REWRITTEN ip -> host, got %q %v", host, ok)
	}
	if _, still := mapping.Get(netip.MustParseAddr("103.21.244.7")); still {
		t.Fatal("mapping must not record the pre-rewrite upstream IP")
	}
}
