package config

import (
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/preferred"

	"go.yaml.in/yaml/v3"
)

func parsePreferredYAML(t *testing.T, s string) []preferred.EntryConfig {
	t.Helper()
	var raw struct {
		DNS struct {
			PreferredIP []RawPreferredIP `yaml:"preferred-ip"`
		} `yaml:"dns"`
	}
	if err := yaml.Unmarshal([]byte(s), &raw); err != nil {
		t.Fatal(err)
	}
	out, err := parsePreferredIP(raw.DNS.PreferredIP)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParseDNSWiresPreferredIP(t *testing.T) {
	var rawCfg RawConfig
	yamlStr := `
dns:
  enable: true
  nameserver: [8.8.8.8]
  default-nameserver: [8.8.8.8]
  preferred-ip:
    - name: cloudflare
      cidr: [103.21.244.0/22]
      ipv6: block
`
	if err := yaml.Unmarshal([]byte(yamlStr), &rawCfg); err != nil {
		t.Fatal(err)
	}
	dnsCfg, err := parseDNS(&rawCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(dnsCfg.PreferredIP) != 1 {
		t.Fatalf("preferred-ip entries lost in parseDNS: %+v", dnsCfg.PreferredIP)
	}
	if dnsCfg.PreferredIP[0].Name != "cloudflare" {
		t.Fatalf("entry name lost: %+v", dnsCfg.PreferredIP[0])
	}
	// validate the CIDR survives newEntry (cidr parse happens there)
	if len(dnsCfg.PreferredIP[0].CIDR) != 1 {
		t.Fatalf("cidr lost: %+v", dnsCfg.PreferredIP[0])
	}
}

func TestParsePreferredIPFull(t *testing.T) {
	cfgs := parsePreferredYAML(t, `
dns:
  preferred-ip:
    - name: cloudflare
      cidr:
        - 173.245.48.0/20
        - 2606:4700::/32
      ipv6: block
      answer-count: 3
      ttl-cap: 30
      persist: false
      speedtest:
        url: https://speed.example.com/__down?bytes=100000000
        interval: 12h
        disable-download: false
        threads: 100
        tcp-port: 8443
        ping-times: 2
        download-count: 5
        download-time: 5s
        max-delay: 500ms
        min-delay: 40ms
        max-loss-rate: 0.25
        min-speed: 2.5
`)
	if len(cfgs) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(cfgs))
	}
	c := cfgs[0]
	if c.Name != "cloudflare" || len(c.CIDR) != 2 {
		t.Fatalf("name/cidr mismatch: %+v", c)
	}
	if string(c.IPv6) != "block" {
		t.Fatalf("ipv6 mode lost: %q", c.IPv6)
	}
	if c.AnswerCount != 3 || c.TTLCap != 30 || c.Persist {
		t.Fatalf("scalar fields mismatch: %+v", c)
	}
	st := c.SpeedTest
	if st.URL == "" || st.Interval != 12*time.Hour || st.Threads != 100 || st.TCPPort != 8443 {
		t.Fatalf("speedtest fields mismatch: %+v", st)
	}
	if st.PingTimes != 2 || st.DownloadCount != 5 || st.DownloadTimeout != 5*time.Second {
		t.Fatalf("speedtest count fields mismatch: %+v", st)
	}
	if st.MaxDelay != 500*time.Millisecond || st.MinDelay != 40*time.Millisecond {
		t.Fatalf("delay filters mismatch: %+v", st)
	}
	if st.MaxLossRate != 0.25 || st.MinSpeedMB != 2.5 {
		t.Fatalf("loss/speed filters mismatch: %+v", st)
	}
}

func TestParsePreferredIPDefaults(t *testing.T) {
	cfgs := parsePreferredYAML(t, `
dns:
  preferred-ip:
    - name: cf
      cidr: [103.21.244.0/22]
`)
	c := cfgs[0]
	if string(c.IPv6) != "" { // normalized later in newEntry; raw keeps ""
		t.Fatalf("empty ipv6 should stay empty (default), got %q", c.IPv6)
	}
	if c.AnswerCount != 5 || c.TTLCap != 60 || !c.Persist {
		t.Fatalf("defaults wrong: %+v", c)
	}
	if c.SpeedTest.Interval != 0 { // 0 -> engine default 24h
		t.Fatalf("interval default should be 0 (engine default), got %v", c.SpeedTest.Interval)
	}
	if c.SpeedTest.Threads != 200 || c.SpeedTest.TCPPort != 443 || c.SpeedTest.PingTimes != 4 {
		t.Fatalf("speedtest defaults wrong: %+v", c.SpeedTest)
	}
}

func TestParsePreferredIPBareSeconds(t *testing.T) {
	cfgs := parsePreferredYAML(t, `
dns:
  preferred-ip:
    - name: cf
      cidr: [103.21.244.0/22]
      speedtest:
        interval: 3600
        download-time: 10
`)
	if cfgs[0].SpeedTest.Interval != time.Hour {
		t.Fatalf("bare number interval should be seconds, got %v", cfgs[0].SpeedTest.Interval)
	}
	if cfgs[0].SpeedTest.DownloadTimeout != 10*time.Second {
		t.Fatalf("bare number download-time should be seconds, got %v", cfgs[0].SpeedTest.DownloadTimeout)
	}
}

func TestParsePreferredIPErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"missing name", `
dns:
  preferred-ip:
    - cidr: [103.21.244.0/22]
`},
		{"duplicate name", `
dns:
  preferred-ip:
    - {name: cf, cidr: [103.21.244.0/22]}
    - {name: cf, cidr: [1.0.0.0/24]}
`},
		{"missing cidr", `
dns:
  preferred-ip:
    - name: cf
`},
		{"bad ipv6 mode", `
dns:
  preferred-ip:
    - {name: cf, cidr: [103.21.244.0/22], ipv6: nuke}
`},
		{"bad cidr", `
dns:
  preferred-ip:
    - {name: cf, cidr: ["not-a-cidr"]}
`},
		{"interval too small", `
dns:
  preferred-ip:
    - name: cf
      cidr: [103.21.244.0/22]
      speedtest: {interval: 30s}
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var raw struct {
				DNS struct {
					PreferredIP []RawPreferredIP `yaml:"preferred-ip"`
				} `yaml:"dns"`
			}
			if err := yaml.Unmarshal([]byte(tc.yaml), &raw); err != nil {
				t.Fatal(err)
			}
			// bad cidr is caught in newEntry (preferred pkg), not parse; skip that here
			if tc.name == "bad cidr" {
				return
			}
			if _, err := parsePreferredIP(raw.DNS.PreferredIP); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}
