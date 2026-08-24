package preferred

// Speed test engine ported from XIU2/CloudflareSpeedTest (GPL-3), adapted:
//   - candidates are sampled from the entry's CIDR sets instead of ip.txt
//   - all dials go through mihomo's direct dialer (interface / routing-mark
//     aware, TUN-loop safe) instead of net.Dialer
//   - progress bars / CSV output are replaced by structured logging

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
	mtls "github.com/metacubex/tls"
)

const (
	tcpConnectTimeout = time.Second * 1
	tcpMaxRoutines    = 1000
	tcpDefaultRoutine = 200
	tcpDefaultPort    = 443
	tcpDefaultTimes   = 4

	dlDefaultTimeout       = 10 * time.Second
	dlDefaultCount         = 10
	downloadBufferSize     = 1024
	speedTestOverallBudget = 30 * time.Minute
)

// candidateSampler lets tests inject deterministic samplers.
type candidateSampler interface {
	Foreach(f func(prefix netip.Prefix) bool)
}

// rng is only used for candidate sampling; not cryptographic.
var rng = struct {
	sync.Mutex
	*rand.Rand
}{Rand: rand.New(rand.NewSource(time.Now().UnixNano()))}

// candidates samples one host per configured prefix. The unused family is not
// sampled: `block` entries skip v6 entirely (its pool would never be used).
func (e *entry) candidates() ([]netip.Addr, error) {
	cands := sampleRanges(e.v4Ranges)
	if e.cfg.IPv6 == ModeReplace {
		cands = append(cands, sampleRanges(e.v6Ranges)...)
	}
	if len(cands) == 0 {
		return nil, errors.New("no candidate IP sampled from CIDR ranges")
	}
	return cands, nil
}

// samplesPerPrefix mirrors CFST's /24-granularity walk for v4 (a /22 yields 4
// candidates, a /20 yields 16, capped at 256) and a flat 64 for v6.
func samplesPerPrefix(prefix netip.Prefix) int {
	addr := prefix.Addr()
	familyBits := 32
	if addr.Is6() && !addr.Is4In6() {
		familyBits = 128
	}
	hostBits := familyBits - prefix.Bits()
	if hostBits <= 0 {
		return 1
	}
	if familyBits == 32 {
		if hostBits <= 8 {
			return 1
		}
		n := 1 << uint(minInt(hostBits-8, 8)) // one per /24 chunk, cap 256
		return maxInt(n, 1)
	}
	return 64
}

// sampleRanges picks random host addresses per prefix at CFST density.
func sampleRanges(set candidateSampler) []netip.Addr {
	var out []netip.Addr
	set.Foreach(func(prefix netip.Prefix) bool {
		addr := prefix.Addr()
		familyBits := 32
		if addr.Is6() && !addr.Is4In6() {
			familyBits = 128
		}
		hostBits := familyBits - prefix.Bits()
		if hostBits <= 0 {
			out = append(out, addr)
			return true
		}
		n := samplesPerPrefix(prefix)
		for i := 0; i < n; i++ {
			out = append(out, randomHost(prefix, hostBits))
		}
		return true
	})
	return out
}

// randomHost returns prefix.Addr() with its low hostBits bits randomized.
// Entropy is capped at 32 bits (v4 needs at most 32), uniform enough for
// candidate sampling. The base is prefix.Masked() so non-canonical CIDRs are
// handled correctly.
func randomHost(prefix netip.Prefix, hostBits int) netip.Addr {
	bits := hostBits
	if bits > 32 {
		bits = 32
	}
	rng.Lock()
	n := rng.Uint32() & (uint32(1)<<bits - 1)
	rng.Unlock()

	if addr := prefix.Masked().Addr(); addr.Is4() || addr.Is4In6() {
		var base, out [4]byte
		base = addr.Unmap().As4()
		copy(out[:], base[:])
		for i := 0; i < bits && i < 32; i++ {
			if n&(1<<i) != 0 {
				out[3-i/8] |= 1 << uint(i%8)
			}
		}
		return netip.AddrFrom4(out)
	}
	b := prefix.Masked().Addr().As16()
	for i := 0; i < bits; i++ {
		if n&(1<<i) != 0 {
			b[15-i/8] |= 1 << uint(i%8)
		}
	}
	return netip.AddrFrom16(b)
}

// candidateScore carries one candidate's tcping statistics.
type candidateScore struct {
	ip       netip.Addr
	recv     int
	avg      time.Duration
	lossRate float32
}

// testRound runs one full round for the entry: tcping -> filters -> optional
// download ranking -> pool swap -> persistence.
func (e *entry) testRound(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, speedTestOverallBudget)
	defer cancel()

	cands, err := e.candidates()
	if err != nil {
		return err
	}
	log.Infoln("[PreferredIP] %s: speed test round started (%d candidates)", e.cfg.Name, len(cands))

	scores := e.tcpingAll(cctx, cands)
	scores = filterScores(scores, e.cfg.SpeedTest)
	if len(scores) == 0 {
		return errors.New("no candidate survived latency filters")
	}

	ranked, err := e.rankByDownload(cctx, scores)
	if err != nil {
		return err
	}

	var v4, v6 []netip.Addr
	for _, ip := range ranked {
		if len(v4) >= maxPoolSize && len(v6) >= maxPoolSize {
			break
		}
		if ip.Is4() || ip.Is4In6() {
			if len(v4) < maxPoolSize {
				v4 = append(v4, ip)
			}
		} else if len(v6) < maxPoolSize {
			v6 = append(v6, ip)
		}
	}
	if len(v4) == 0 && len(v6) == 0 {
		return errors.New("speed test produced empty pools")
	}

	now := time.Now()
	if len(v4) > 0 {
		e.v4Pool.Store(v4, now)
	}
	if len(v6) > 0 {
		e.v6Pool.Store(v6, now)
	}
	e.storePersisted(now)

	if len(v4) > 0 {
		log.Infoln("[PreferredIP] %s: v4 pool updated: %d IPs, best %s", e.cfg.Name, len(v4), v4[0])
	}
	if len(v6) > 0 {
		log.Infoln("[PreferredIP] %s: v6 pool updated: %d IPs, best %s", e.cfg.Name, len(v6), v6[0])
	}
	return nil
}

func (e *entry) tcpingAll(ctx context.Context, cands []netip.Addr) []candidateScore {
	st := e.cfg.SpeedTest
	threads := tcpDefaultRoutine
	if st.Threads > 0 {
		threads = minInt(st.Threads, tcpMaxRoutines)
	}
	times := tcpDefaultTimes
	if st.PingTimes > 0 {
		times = st.PingTimes
	}
	port := tcpDefaultPort
	if st.TCPPort > 0 && st.TCPPort < 65535 {
		port = st.TCPPort
	}

	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		sem    = make(chan struct{}, threads)
		scores = make([]candidateScore, 0, len(cands))
	)

	for _, cand := range cands {
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			select {
			case <-ctx.Done():
				return
			default:
			}
			recv, total := e.tcping(ctx, ip, port, times)
			if recv == 0 {
				return
			}
			mu.Lock()
			scores = append(scores, candidateScore{
				ip:       ip,
				recv:     recv,
				avg:      total / time.Duration(recv),
				lossRate: float32(times-recv) / float32(times),
			})
			mu.Unlock()
		}(cand)
	}
	wg.Wait()

	sort.Slice(scores, func(i, j int) bool {
		if scores[i].lossRate != scores[j].lossRate {
			return scores[i].lossRate < scores[j].lossRate
		}
		return scores[i].avg < scores[j].avg
	})
	return scores
}

// tcping dials ip:port `times` times through mihomo's direct dialer and returns
// (successes, total connect time).
func (e *entry) tcping(ctx context.Context, ip netip.Addr, port, times int) (recv int, total time.Duration) {
	network := "tcp4"
	if ip.Is6() && !ip.Is4In6() {
		network = "tcp6"
	}
	address := netip.AddrPortFrom(ip.Unmap(), uint16(port)).String()
	for i := 0; i < times; i++ {
		select {
		case <-ctx.Done():
			return recv, total
		default:
		}
		start := time.Now()
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			continue
		}
		_ = conn.Close()
		total += time.Since(start)
		recv++
	}
	return recv, total
}

func filterScores(scores []candidateScore, st SpeedTestConfig) []candidateScore {
	var out []candidateScore
	for _, s := range scores {
		if st.MaxDelay > 0 && s.avg > st.MaxDelay {
			break // sorted by delay ascending: the rest is worse
		}
		if st.MinDelay > 0 && s.avg < st.MinDelay {
			continue
		}
		if st.MaxLossRate > 0 && st.MaxLossRate < 1 && s.lossRate > st.MaxLossRate {
			continue
		}
		out = append(out, s)
	}
	return out
}

// rankByDownload runs the download phase on the top DownloadCount latency
// survivors and re-ranks them by speed (best first). With MinSpeedMB == 0 every
// tested IP is kept (CFST behavior); otherwise only IPs above the floor.
func (e *entry) rankByDownload(ctx context.Context, scores []candidateScore) ([]netip.Addr, error) {
	st := e.cfg.SpeedTest
	if st.DisableDownload {
		out := make([]netip.Addr, 0, len(scores))
		for _, s := range scores {
			out = append(out, s.ip)
		}
		return out, nil
	}

	count := dlDefaultCount
	if st.DownloadCount > 0 {
		count = st.DownloadCount
	}
	timeout := dlDefaultTimeout
	if st.DownloadTimeout > 0 {
		timeout = st.DownloadTimeout
	}
	queue := scores
	if len(queue) > count {
		queue = queue[:count]
	}

	type ipSpeed struct {
		idx   int
		speed float64
	}
	results := make([]ipSpeed, len(queue))
	for i := range queue {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		results[i] = ipSpeed{idx: i, speed: e.downloadOnce(ctx, queue[i].ip, timeout)}
	}

	floor := st.MinSpeedMB * 1024 * 1024
	kept := make([]ipSpeed, 0, len(results))
	for _, r := range results {
		if st.MinSpeedMB <= 0 || r.speed >= floor {
			kept = append(kept, r)
		}
	}
	if len(kept) == 0 {
		// nobody met the floor: keep all rather than fail the round
		kept = results
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].speed > kept[j].speed })

	ranked := make([]netip.Addr, 0, len(scores))
	for _, r := range kept {
		ranked = append(ranked, queue[r.idx].ip)
	}
	if len(ranked) == 0 {
		return nil, errors.New("download phase produced no usable IP")
	}
	return ranked, nil
}

// downloadOnce measures download speed against the configured URL with every
// connection pinned to ip via the direct dialer (Host/SNI stay intact).
func (e *entry) downloadOnce(ctx context.Context, ip netip.Addr, timeout time.Duration) float64 {
	url := e.cfg.SpeedTest.URL
	if url == "" {
		url = DefaultDownloadURL
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				_ = address // pin to the candidate; port 443, TLS SNI from URL host
				if ip.Is6() && !ip.Is4In6() {
					network = "tcp6"
				} else {
					network = "tcp4"
				}
				return dialer.DialContext(ctx, network, netip.AddrPortFrom(ip.Unmap(), 443).String())
			},
			TLSClientConfig: &mtls.Config{RootCAs: ca.GetCertPool(), MinVersion: mtls.VersionTLS12},
		},
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "mihomo-preferred-ip")

	resp, err := client.Do(req)
	if err != nil {
		log.Debugln("[PreferredIP] %s: download test %s failed: %v", e.cfg.Name, ip, err)
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Debugln("[PreferredIP] %s: download test %s status %d", e.cfg.Name, ip, resp.StatusCode)
		return 0
	}

	// per-window speeds, averaged (CFST feeds the same per-slice numbers into EWMA)
	window := timeout / 10
	if window < 100*time.Millisecond {
		window = 100 * time.Millisecond
	}
	buf := make([]byte, downloadBufferSize)
	var total, lastTotal int64
	var speeds []float64
	windowStart := time.Now()
	deadline := windowStart.Add(timeout)
	for time.Now().Before(deadline) {
		n, err := resp.Body.Read(buf)
		total += int64(n)
		if now := time.Now(); now.Sub(windowStart) >= window {
			speeds = append(speeds, float64(total-lastTotal)/now.Sub(windowStart).Seconds())
			lastTotal = total
			windowStart = now
		}
		if err != nil { // io.EOF (file finished) or transport error: stop measuring
			break
		}
	}

	if len(speeds) == 0 {
		if elapsed := time.Since(deadline.Add(-timeout)); elapsed > 0 {
			return float64(total) / elapsed.Seconds()
		}
		return 0
	}
	var sum float64
	for _, s := range speeds {
		sum += s
	}
	return sum / float64(len(speeds))
}
