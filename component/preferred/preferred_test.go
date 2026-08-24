package preferred

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func testEntry(t *testing.T, ipv6 IPv6Mode) *entry {
	t.Helper()
	e, err := newEntry(EntryConfig{
		Name:        "cf",
		CIDR:        []string{"103.21.244.0/22", "2606:4700::/32"},
		IPv6:        ipv6,
		AnswerCount: 2,
		TTLCap:      60,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func testManager(t *testing.T, entries ...*entry) *Manager {
	t.Helper()
	m := NewManager()
	list := entries
	m.entries.Store(&list)
	return m
}

var (
	poolV4 = []netip.Addr{
		netip.MustParseAddr("104.16.1.1"),
		netip.MustParseAddr("104.16.2.2"),
		netip.MustParseAddr("104.16.3.3"),
	}
	poolV6 = []netip.Addr{
		netip.MustParseAddr("2606:4700:4700::1111"),
		netip.MustParseAddr("2606:4700:4700::2222"),
	}
)

func TestMatchFirstEntryWins(t *testing.T) {
	inCF := netip.MustParseAddr("103.21.244.10")
	inCF2 := netip.MustParseAddr("103.21.245.10")
	outCF := netip.MustParseAddr("1.2.3.4")

	e1 := testEntry(t, ModeReplace)
	e2 := testEntry(t, ModeReplace) // same ranges, second entry
	e2.cfg.Name = "cf2"
	m := testManager(t, e1, e2)

	if got := m.Match([]netip.Addr{outCF}, false); got != nil {
		t.Fatalf("non-CF ip matched entry %s", got.cfg.Name)
	}
	if got := m.Match([]netip.Addr{inCF, outCF}, false); got != e1 {
		t.Fatalf("first-match-wins violated: got %s", got.cfg.Name)
	}
	// any ip in set counts
	if got := m.Match([]netip.Addr{outCF, inCF2}, false); got != e1 {
		t.Fatalf("set match failed")
	}
}

func TestMatchFamilySeparation(t *testing.T) {
	e := testEntry(t, ModeReplace)
	m := testManager(t, e)

	cf6 := netip.MustParseAddr("2606:4700::1")
	if got := m.Match([]netip.Addr{cf6}, false); got != nil {
		t.Fatal("v6 ip must not match when isV6=false")
	}
	if got := m.Match([]netip.Addr{cf6}, true); got != e {
		t.Fatal("v6 ip should match when isV6=true")
	}
}

func TestRewriteLookupPassthrough(t *testing.T) {
	m := testManager(t, testEntry(t, ModeReplace))

	ips := []netip.Addr{netip.MustParseAddr("1.2.3.4")}
	if got := m.RewriteLookup(ips, false); got != nil {
		t.Fatalf("non-matched lookup must passthrough, got %v", got)
	}

	// matched but pool empty (first test pending): passthrough, not block
	cf := []netip.Addr{netip.MustParseAddr("103.21.244.5")}
	if got := m.RewriteLookup(cf, false); got != nil {
		t.Fatalf("empty pool must passthrough, got %v", got)
	}
}

func TestRewriteLookupReplacesWithPool(t *testing.T) {
	e := testEntry(t, ModeReplace)
	e.v4Pool.Store(poolV4, time.Now())
	m := testManager(t, e)

	cf := []netip.Addr{
		netip.MustParseAddr("103.21.244.5"),
		netip.MustParseAddr("103.21.246.9"),
	}
	got := m.RewriteLookup(cf, false)
	if len(got) != 2 { // answer-count = 2 trims the 3-IP pool
		t.Fatalf("expected pool trimmed to answer count 2, got %v", got)
	}
	if got[0] != poolV4[0] || got[1] != poolV4[1] {
		t.Fatalf("pool order not preserved: %v", got)
	}
}

func TestRewriteLookupBlocksV6(t *testing.T) {
	e := testEntry(t, ModeBlock)
	e.v4Pool.Store(poolV4, time.Now())
	e.v6Pool.Store(poolV6, time.Now()) // even with a v6 pool, block wins
	m := testManager(t, e)

	cf6 := []netip.Addr{netip.MustParseAddr("2606:4700::64")}
	got := m.RewriteLookup(cf6, true)
	if got == nil || len(got) != 0 {
		t.Fatalf("ipv6=block must return empty non-nil slice, got %v", got)
	}
}

func TestAnswerPoolNotReady(t *testing.T) {
	e := testEntry(t, ModeReplace)
	if pool := e.AnswerPool(false); pool != nil {
		t.Fatalf("no pool stored must yield nil, got %v", pool)
	}
	e.v6Pool.Store(nil, time.Now()) // stored-but-nil (tested, nothing survived)
	if pool := e.AnswerPool(true); pool != nil {
		t.Fatalf("stored nil pool must yield nil, got %v", pool)
	}
}

func TestSamplesPerPrefix(t *testing.T) {
	cases := []struct {
		prefix string
		want   int
	}{
		{"103.21.244.7/32", 1}, // single host
		{"103.21.244.0/28", 1}, // hostBits < 8
		{"103.21.244.0/22", 4}, // CFST: one per /24 chunk
		{"173.245.48.0/20", 16},
		{"1.0.0.0/8", 256},     // capped
		{"2606:4700::/32", 64}, // v6 flat
	}
	for _, tc := range cases {
		if got := samplesPerPrefix(netip.MustParsePrefix(tc.prefix)); got != tc.want {
			t.Errorf("%s: want %d samples, got %d", tc.prefix, tc.want, got)
		}
	}
}

func TestRandomHostStaysInPrefix(t *testing.T) {
	prefix := netip.MustParsePrefix("103.21.244.0/22")
	for i := 0; i < 2000; i++ {
		ip := randomHost(prefix, 10)
		if !prefix.Contains(ip) {
			t.Fatalf("sampled %s outside %s", ip, prefix)
		}
	}
	p6 := netip.MustParsePrefix("2606:4700::/32")
	for i := 0; i < 2000; i++ {
		ip := randomHost(p6, 96)
		if !p6.Contains(ip) {
			t.Fatalf("sampled %s outside %s", ip, p6)
		}
	}
}

func TestCandidatesSkipsV6WhenBlock(t *testing.T) {
	e := testEntry(t, ModeBlock)
	cands, err := e.candidates()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cands {
		if c.Is6() && !c.Is4In6() {
			t.Fatalf("block entry must not sample v6, got %v", c)
		}
	}
}

func TestFilterScores(t *testing.T) {
	st := SpeedTestConfig{MaxDelay: 300 * time.Millisecond, MaxLossRate: 0.5}
	scores := []candidateScore{
		{ip: netip.MustParseAddr("1.1.1.1"), avg: 100 * time.Millisecond, lossRate: 0.0},
		{ip: netip.MustParseAddr("1.1.1.2"), avg: 200 * time.Millisecond, lossRate: 0.75}, // loss > 0.5
		{ip: netip.MustParseAddr("1.1.1.3"), avg: 500 * time.Millisecond, lossRate: 0.0},  // delay > 300ms
	}
	got := filterScores(scores, st)
	if len(got) != 1 || got[0].ip != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("unexpected filter result: %+v", got)
	}
}

func TestScheduleCancelSafe(t *testing.T) {
	// entries with an unreachable range still cancel cleanly on ctx.Done
	e := testEntry(t, ModeReplace)
	ctx, cancel := context.WithCancel(context.Background())
	go e.schedule(ctx)
	cancel() // must not leak/panic; goroutine exits on next select
	time.Sleep(50 * time.Millisecond)
}
