package preferred

import (
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/bbolt"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/log"
)

// Pool persistence into cache.db (bbolt), mirroring how fake-ip persists its
// state. Layout: bucket "preferredip", key = entry name, value = JSON of
// {v4: [...], v6: [...], tested_at: RFC3339}. On reload a persisted pool is
// served immediately; when older than the test interval the scheduler
// refreshes it right away (see manager.go schedule).

var bucketPreferredIP = []byte("preferredip")

type persistedEntry struct {
	V4       []string  `json:"v4,omitempty"`
	V6       []string  `json:"v6,omitempty"`
	TestedAt time.Time `json:"tested_at"`
}

func (e *entry) storePersisted(testedAt time.Time) {
	if !e.cfg.Persist {
		return
	}
	db := cachefile.Cache().DB
	if db == nil {
		return
	}
	pe := persistedEntry{TestedAt: testedAt}
	if p := e.v4Pool.Load(); p != nil {
		pe.V4 = addrStrings(p.IPs)
	}
	if p := e.v6Pool.Load(); p != nil {
		pe.V6 = addrStrings(p.IPs)
	}
	value, err := json.Marshal(pe)
	if err != nil {
		log.Warnln("[PreferredIP] %s: marshal persisted pool: %v", e.cfg.Name, err)
		return
	}
	if err = storePool(db, e.cfg.Name, value); err != nil {
		log.Warnln("[PreferredIP] %s: persist pool: %v", e.cfg.Name, err)
	}
}

func storePool(db *bbolt.DB, key string, value []byte) error {
	return db.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketPreferredIP)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(key), value)
	})
}

func (e *entry) loadPersisted() {
	if !e.cfg.Persist {
		return
	}
	value, ok := loadPool(e.cfg.Name)
	if !ok || len(value) == 0 {
		return
	}
	var pe persistedEntry
	if err := json.Unmarshal(value, &pe); err != nil {
		log.Warnln("[PreferredIP] %s: unmarshal persisted pool: %v", e.cfg.Name, err)
		return
	}
	if v4 := parseAddrs(pe.V4); len(v4) > 0 {
		e.v4Pool.Store(v4, pe.TestedAt)
		log.Infoln("[PreferredIP] %s: loaded persisted v4 pool (%d IPs, tested at %s)", e.cfg.Name, len(v4), pe.TestedAt.Format(time.RFC3339))
	}
	if v6 := parseAddrs(pe.V6); len(v6) > 0 && e.cfg.IPv6 == ModeReplace {
		e.v6Pool.Store(v6, pe.TestedAt)
		log.Infoln("[PreferredIP] %s: loaded persisted v6 pool (%d IPs)", e.cfg.Name, len(v6))
	}
}

func loadPool(key string) ([]byte, bool) {
	db := cachefile.Cache().DB
	if db == nil {
		return nil, false
	}
	var value []byte
	err := db.View(func(t *bbolt.Tx) error {
		bucket := t.Bucket(bucketPreferredIP)
		if bucket == nil {
			return nil
		}
		if v := bucket.Get([]byte(key)); v != nil {
			value = append(value, v...) // copy: only valid inside the tx
		}
		return nil
	})
	if err != nil || len(value) == 0 {
		return nil, false
	}
	return value, true
}

func parseAddrs(ss []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		ip, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		out = append(out, ip.Unmap())
	}
	return out
}
