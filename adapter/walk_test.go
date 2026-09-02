package adapter

import (
	"context"
	"testing"
	"time"
)

func TestHeyboxURLTestDelegationWalk(t *testing.T) {
	mapping := map[string]any{
		"name": "walk-test", "type": "heybox",
		"heybox-id": 1, "pkey": "x", "acc-id": 356, "game-id": 353,
		"server-region": 1001, "node-name": "日本3", "acc-mode": 1, "transport-proto": "udp",
		"echo-addr": "127.0.0.1:1", // 无人监听 → echo 失败
		"rtt-avg":   45,            // 兜底应生效
	}
	p, err := ParseProxy(mapping)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	delay, err := p.URLTest(context.Background(), "http://www.baidu.com/", nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("URLTest: %v", err)
	}
	if delay != 45 {
		t.Fatalf("delay = %d, want 45 (rtt-avg fallback)", delay)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("delegation not effective: took %v (real dial path)", elapsed)
	}
	t.Logf("OK: %dms in %v (delegated, no real dial)", delay, elapsed)
}
