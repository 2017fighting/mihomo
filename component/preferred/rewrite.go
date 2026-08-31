package preferred

import "net/netip"

// Rewrite decision API shared by both hooks:
//
//   - DNS server path: dns/middleware.go withPreferredIP performs D.Msg
//     surgery (records/TTL) using Match/BlockIPv6/AnswerPool/TTLCap below.
//   - Internal path: dns/resolver.go lookupIP uses RewriteLookup, which works
//     on plain IP slices.
//
// Semantics (whole-answer): when any IP of the family matches an entry, the
// ENTIRE family portion is rewritten from that entry's pool (first-match-wins
// across entries). Passthrough whenever no entry matches or no pool is ready.

// Name is the entry's configured name (logging/REST).
func (e *entry) Name() string {
	return e.cfg.Name
}

// BlockIPv6 reports whether this entry should answer matched AAAA queries with
// an empty answer instead of rewriting.
func (e *entry) BlockIPv6() bool {
	return e.cfg.IPv6 == ModeBlock
}

// AnswerPool returns the current pool for one family trimmed to the answer
// count; nil means passthrough.
// Kept next to Match so the middleware can fetch it atomically-ish: pools swap
// only at round completion, never partially.
func (e *entry) AnswerPool(isV6 bool) []netip.Addr {
	return e.pool(isV6)
}

// TTLCap is the rewrite TTL ceiling in seconds.
func (e *entry) TTLCap() uint32 {
	return e.ttlCap()
}

// RewriteLookup rewrites an internal lookup result (resolver.lookupIP exit).
//
// Return values:
//
//	nil            -> passthrough (no entry matched)
//	non-nil, empty -> blocked (ipv6: block matched; caller should treat as no IPs)
//	non-nil        -> replaced with the pool
func (m *Manager) RewriteLookup(ips []netip.Addr, isV6 bool) []netip.Addr {
	entry := m.Match(ips, isV6)
	if entry == nil {
		return nil
	}
	if isV6 && entry.BlockIPv6() {
		return []netip.Addr{}
	}
	pool := entry.AnswerPool(isV6)
	if len(pool) == 0 {
		return nil // pool not ready -> passthrough
	}
	out := make([]netip.Addr, len(pool))
	copy(out, pool)
	return out
}
