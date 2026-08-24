package preferred

import (
	"net/netip"
	"sync/atomic"
	"time"
)

// atomicPool is an atomically swappable poolState pointer. Rewrites always read
// a consistent snapshot; a finished speed-test round installs a whole new state.
type atomicPool struct {
	p atomic.Pointer[poolState]
}

func (a *atomicPool) Load() *poolState {
	return a.p.Load()
}

func (a *atomicPool) Store(ips []netip.Addr, testedAt time.Time) {
	a.p.Store(&poolState{IPs: ips, TestedAt: testedAt})
}

func (a *atomicPool) Age() (time.Duration, bool) {
	p := a.p.Load()
	if p == nil || len(p.IPs) == 0 {
		return 0, false
	}
	return time.Since(p.TestedAt), true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
