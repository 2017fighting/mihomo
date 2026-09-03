// Package preferred implements DNS IP preference (IP preference): DNS answers whose
// A/AAAA records fall inside configured CIDR range sets (e.g. Cloudflare anycast
// ranges) are rewritten to the top-N IPs produced by an embedded speed test.
//
// Semantics (see docs/adr/0001):
//   - Matching is pure IP semantics, domain independent.
//   - Rewrite happens OUTSIDE the DNS cache; the cache always stores upstream truth.
//   - Passthrough whenever no pool is ready (first test pending, test failed, file
//     missing): the feature degrades to non-existent.
//
// This package must not import mihomo's dns or config packages (they import this).
package preferred

import (
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/cidr"
)

const (
	ModeReplace IPv6Mode = "replace" // rewrite AAAA from the v6 pool (default)
	ModeBlock   IPv6Mode = "block"   // answer AAAA with an empty answer once matched

	DefaultAnswerCount = 5
	DefaultTTLCapSec   = 60
	DefaultInterval    = 24 * time.Hour
	RetryBackoff       = 10 * time.Minute // retest backoff after a fully failed round

	maxAnswerCount = 16
	maxPoolSize    = 32 // bound persisted/in-memory pool size
)

type IPv6Mode string

// SpeedTestConfig holds all tunables of one speed-test round.
type SpeedTestConfig struct {
	URL             string        // download test URL; "" -> DefaultDownloadURL
	Interval        time.Duration // period between rounds
	DisableDownload bool          // latency-only ranking
	Threads         int           // tcping concurrency
	TCPPort         int           // port used by tcping (and pinned dials)
	PingTimes       int           // tcping attempts per candidate
	DownloadCount   int           // how many top-latency IPs get download tested
	DownloadTimeout time.Duration // per-IP download duration
	MaxDelay        time.Duration // drop candidates above this average delay
	MinDelay        time.Duration // drop candidates below this average delay
	MaxLossRate     float32       // drop candidates above this loss rate [0,1]
	MinSpeedMB      float64       // MB/s floor; 0 keeps everything
}

// DefaultDownloadURL is Cloudflare's official download endpoint. Kept as the
// default instead of third-party redirect services; users are meant to override.
const DefaultDownloadURL = "https://speed.cloudflare.com/__down?bytes=500000000"

// EntryConfig is one dns.preferred-ip list item.
type EntryConfig struct {
	Name        string
	CIDR        []string // drives BOTH rewrite matching and test candidates
	IPv6        IPv6Mode
	AnswerCount int  // N answers returned after rewrite
	TTLCap      int  // seconds; rewritten TTL = min(original, cap)
	Persist     bool // persist pools into cache.db
	SpeedTest   SpeedTestConfig
}

// entry is the runtime form of EntryConfig: immutable CIDR sets plus atomically
// swapped pools. Safe for concurrent use.
type entry struct {
	cfg      EntryConfig
	v4Ranges *cidr.IpCidrSet
	v6Ranges *cidr.IpCidrSet

	v4Pool atomicPool
	v6Pool atomicPool

	testing chan struct{} // buffered(1) nudge channel for manual triggers

	// testingActive mirrors "a round is currently running" for the REST
	// status surface; the channel above cannot be inspected.
	testingActive atomic.Bool
}

func (e *entry) answerCount() int {
	if e.cfg.AnswerCount < 1 {
		return DefaultAnswerCount
	}
	return minInt(e.cfg.AnswerCount, maxAnswerCount)
}

func (e *entry) ttlCap() uint32 {
	if e.cfg.TTLCap < 1 {
		return DefaultTTLCapSec
	}
	return uint32(e.cfg.TTLCap)
}

// pool returns the current pool snapshot for one family, trimmed to the answer
// count. Nil means "not ready" -> passthrough.
func (e *entry) pool(isV6 bool) []netip.Addr {
	var p *poolState
	if isV6 {
		p = e.v6Pool.Load()
	} else {
		p = e.v4Pool.Load()
	}
	if p == nil || len(p.IPs) == 0 {
		return nil
	}
	return p.IPs[:minInt(len(p.IPs), e.answerCount())]
}

// poolState is one successful speed-test round's product: a ranked IP list
// (best first) plus the round completion time.
type poolState struct {
	IPs      []netip.Addr
	TestedAt time.Time
}

func newEntry(cfg EntryConfig) (*entry, error) {
	e := &entry{
		cfg:     cfg,
		testing: make(chan struct{}, 1),
	}
	e.cfg.IPv6 = normalizeIPv6Mode(cfg.IPv6)
	e.v4Ranges = cidr.NewIpCidrSet()
	e.v6Ranges = cidr.NewIpCidrSet()
	for i, s := range cfg.CIDR {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("preferred-ip[%s] cidr[%d] %q: %w", cfg.Name, i, s, err)
		}
		if prefix.Addr().Is4() || prefix.Addr().Is4In6() {
			if err = e.v4Ranges.AddIpCidr(prefix); err != nil {
				return nil, err
			}
		} else {
			if err = e.v6Ranges.AddIpCidr(prefix); err != nil {
				return nil, err
			}
		}
	}
	if err := e.v4Ranges.Merge(); err != nil {
		return nil, err
	}
	if err := e.v6Ranges.Merge(); err != nil {
		return nil, err
	}
	return e, nil
}

func normalizeIPv6Mode(m IPv6Mode) IPv6Mode {
	if m == ModeBlock {
		return ModeBlock
	}
	return ModeReplace
}

func (e *entry) contains(ip netip.Addr) bool {
	if ip.Is4() || ip.Is4In6() {
		return e.v4Ranges.IsContain(ip)
	}
	return e.v6Ranges.IsContain(ip)
}
