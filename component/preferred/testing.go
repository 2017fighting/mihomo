package preferred

import (
	"net/netip"
	"time"
)

// Test-only helpers, exported because the dns package's middleware tests live
// outside this package. Never call from production code paths.

// InstallForTesting swaps the process-wide Default for a manager holding one
// entry built from cfg with preset pools and NO schedulers started. The
// returned func restores the previous Default.
func InstallForTesting(cfg EntryConfig, v4, v6 []netip.Addr) (restore func()) {
	m := NewManager()
	if e, err := newEntry(cfg); err == nil {
		if v4 != nil {
			e.v4Pool.Store(v4, time.Now())
		}
		if v6 != nil {
			e.v6Pool.Store(v6, time.Now())
		}
		list := []*entry{e}
		m.entries.Store(&list)
	}
	old := Default
	Default = m
	return func() { Default = old }
}
