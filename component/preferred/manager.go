package preferred

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
)

// Manager owns all runtime entries. It is swapped wholesale on config reload;
// lookups (Match) run lock-free off an atomic snapshot.
type Manager struct {
	entries atomic.Pointer[[]*entry]
	cancel  context.CancelFunc
	mu      sync.Mutex // serializes Reload/Close
}

// Default is the process-wide manager. An empty manager matches nothing and
// every rewrite degrades to passthrough.
var Default = NewManager()

func NewManager() *Manager {
	m := &Manager{}
	empty := []*entry{}
	m.entries.Store(&empty)
	return m
}

// Reload atomically replaces all entries and their schedulers. Entries of the
// new generation start from persisted pools (cache.db) when available, then run
// their own speed tests. Called with nil on DNS disable.
func (m *Manager) Reload(cfgs []EntryConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}

	entries := make([]*entry, 0, len(cfgs))
	for _, cfg := range cfgs {
		e, err := newEntry(cfg)
		if err != nil {
			log.Errorln("[PreferredIP] skip entry: %v", err)
			continue
		}
		entries = append(entries, e)
	}
	m.entries.Store(&entries)

	if len(entries) == 0 {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	for _, e := range entries {
		e.loadPersisted()
		go e.schedule(ctx)
	}
}

// Close stops all schedulers (process shutdown).
func (m *Manager) Close() {
	m.Reload(nil)
}

// Match returns the first entry (config order) whose ranges contain any of ips.
// First-match-wins is the documented policy for overlapping range sets.
func (m *Manager) Match(ips []netip.Addr, isV6 bool) *entry {
	entries := *m.entries.Load()
	for _, e := range entries {
		for _, ip := range ips {
			if !ip.IsValid() {
				continue
			}
			if (ip.Is6() && !ip.Is4In6()) != isV6 {
				continue
			}
			if e.contains(ip) {
				return e
			}
		}
	}
	return nil
}

// TriggerSpeedTest nudges one entry (by name, or all when name == "") into an
// immediate retest round. Returns false when the name is unknown or a round is
// already running for every targeted entry.
func (m *Manager) TriggerSpeedTest(name string) bool {
	entries := *m.entries.Load()
	triggered := false
	for _, e := range entries {
		if name != "" && e.cfg.Name != name {
			continue
		}
		select {
		case e.testing <- struct{}{}:
			triggered = true
		default:
			// a round is already queued/running for this entry; keep it.
			triggered = triggered || name == ""
		}
	}
	return triggered
}

// Status renders every entry for the REST API.
func (m *Manager) Status() []EntryStatus {
	entries := *m.entries.Load()
	out := make([]EntryStatus, 0, len(entries))
	for _, e := range entries {
		es := EntryStatus{
			Name:        e.cfg.Name,
			IPv6:        string(e.cfg.IPv6),
			AnswerCount: e.answerCount(),
			TTLCap:      int(e.ttlCap()),
			Persist:     e.cfg.Persist,
		}
		if p := e.v4Pool.Load(); p != nil {
			es.V4 = addrStrings(p.IPs)
			es.V4TestedAt = p.TestedAt
		}
		if p := e.v6Pool.Load(); p != nil {
			es.V6 = addrStrings(p.IPs)
			es.V6TestedAt = p.TestedAt
		}
		out = append(out, es)
	}
	return out
}

type EntryStatus struct {
	Name        string    `json:"name"`
	IPv6        string    `json:"ipv6"`
	AnswerCount int       `json:"answer-count"`
	TTLCap      int       `json:"ttl-cap"`
	Persist     bool      `json:"persist"`
	V4          []string  `json:"v4-pool,omitempty"`
	V4TestedAt  time.Time `json:"v4-tested-at,omitzero"`
	V6          []string  `json:"v6-pool,omitempty"`
	V6TestedAt  time.Time `json:"v6-tested-at,omitzero"`
}

func addrStrings(ips []netip.Addr) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// schedule drives this entry's test loop. The first round runs immediately
// when no usable pool exists or the persisted one is stale (older than the
// interval); otherwise it waits until testedAt+interval. Failed rounds keep
// the old pool and retry after RetryBackoff; a REST trigger wakes the loop at
// any time.
func (e *entry) schedule(ctx context.Context) {
	timer := time.NewTimer(e.currentWait())
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.testing: // manual trigger: drain any pending tick first
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}

		var next time.Duration
		if err := e.testRound(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warnln("[PreferredIP] entry %s: speed test round failed (%v), keeping old pool, retrying in %s", e.cfg.Name, err, RetryBackoff)
			next = RetryBackoff
		} else {
			next = e.waitDuration()
		}
		timer.Reset(next)
	}
}

// waitDuration returns how long to sleep after a successful round.
func (e *entry) waitDuration() time.Duration {
	interval := e.cfg.SpeedTest.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	return interval
}

// currentWait returns the wait until the next scheduled round, accounting for a
// possibly still-fresh persisted pool.
func (e *entry) currentWait() time.Duration {
	interval := e.waitDuration()
	if _, ok := e.v4Pool.Age(); ok {
		return time.Until(e.v4Pool.Load().TestedAt.Add(interval))
	}
	if _, ok := e.v6Pool.Age(); ok {
		return time.Until(e.v6Pool.Load().TestedAt.Add(interval))
	}
	// no pool at all: test now
	return time.Duration(0)
}
