package heybox

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLiveProbe 真实环境探针（默认跳过）：
//
//	HEYBOX_LIVE=1 HEYBOX_ID=16651571 HEYBOX_PKEY='MTc4...' \
//	go test ./transport/heybox/ -run TestLiveProbe -v -count=1
//
// 依次验证：hkey 签名的三个控制面接口 → 会话分配 → 节点 TCP CONNECT → UDP ASSOCIATE。
// 任一步失败即停并打印服务端返回，用于定位 502 的根因。
func TestLiveProbe(t *testing.T) {
	if os.Getenv("HEYBOX_LIVE") == "" {
		t.Skip("set HEYBOX_LIVE=1 HEYBOX_ID=... HEYBOX_PKEY=... to run live probe")
	}
	id, err := strconv.ParseInt(os.Getenv("HEYBOX_ID"), 10, 64)
	if err != nil || id == 0 {
		t.Fatal("bad HEYBOX_ID")
	}
	pkey := os.Getenv("HEYBOX_PKEY")
	if pkey == "" {
		t.Fatal("empty HEYBOX_PKEY")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	api := NewAPIClient(id, pkey, "", "")

	// 1. 游戏枚举
	games, err := api.UsedGameList(ctx)
	if err != nil {
		t.Fatalf("step1 UsedGameList: %v", err)
	}
	var switchGame *GameEntry
	for i := range games {
		g := games[i]
		if g.DeviceType == "Switch" || g.AccID == 356 {
			switchGame = &g
		}
	}
	if switchGame == nil {
		t.Fatalf("step1: no Switch entry in %d games", len(games))
	}
	t.Logf("step1 OK: %s acc_id=%d game_id=%d districts=%v", switchGame.Name, switchGame.AccID, switchGame.GameID, switchGame.AccDistrict)

	// 2. 节点枚举（第一个大区）
	d := switchGame.AccDistrict[0]
	nodes, err := api.AbroadNodeList(ctx, switchGame.AccID, d.ID)
	if err != nil {
		t.Fatalf("step2 AbroadNodeList(%d): %v", d.ID, err)
	}
	if len(nodes) == 0 {
		t.Fatal("step2: empty node list")
	}
	for _, n := range nodes {
		t.Logf("  node %q rtt=%dms hop=%s", n.Name, n.RTTAvg, n.FirstHopLocation)
	}

	// 3. 会话分配（hkey 关键验证点）
	cfg, err := api.NodeConfig(ctx, NodeConfigParams{
		AccID:        switchGame.AccID,
		GameID:       switchGame.GameID,
		ServerRegion: d.ID,
		NodeName:     nodes[0].Name,
	})
	if err != nil {
		t.Fatalf("step3 NodeConfig (hkey/pkey validation): %v", err)
	}
	t.Logf("step3 OK: session=%d ver=%d aes_key=%q xor=%q udp=%s tcp=%s",
		cfg.SessionID, cfg.Ver, cfg.AESKey, cfg.XorBytes, cfg.EntryNode(), cfg.TCPNode())

	// 4. 节点 TCP CONNECT（默认 conntest，可用 HEYBOX_TARGET 覆盖）
	target := os.Getenv("HEYBOX_TARGET")
	if target == "" {
		target = "conntest.nintendowifi.net:80"
	}
	client := &Client{
		Node: cfg.TCPNode(),
		Ver:  cfg.Ver,
		Sess: &Session{HeyboxID: id, SessionID: cfg.SessionID, Username: pkey, AESKey: decodeKey(cfg.AESKey)},
	}
	conn, resp, err := client.DialTCP(ctx, target)
	if err != nil {
		t.Fatalf("step4 DialTCP: %v (rep=%d)", err, respRep(resp))
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	hostHeader := target
	if i := strings.LastIndex(hostHeader, ":"); i > 0 {
		hostHeader = hostHeader[:i]
	}
	// echo/DNS 模式：发送已知字节，回显即为密文（可推导任意长度密钥流）
	var req []byte
	isEcho := strings.Contains(target, "echo")
	isDNS := strings.HasSuffix(target, ":53")
	switch {
	case isEcho:
		req = make([]byte, 96)
		for i := range req {
			req[i] = byte(0x41 + i%26) // ABCDEF... 循环
		}
	case isDNS:
		// DNS A 查询 nintendo.com（TCP DNS 带 2 字节长度前缀），事务 ID 0x1234；
		// 应答原样回显 question 段
		q := []byte{
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			8, 'n', 'i', 'n', 't', 'e', 'n', 'd', 'o', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
		}
		req = append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)
	default:
		req = []byte("GET / HTTP/1.0\r\nHost: " + hostHeader + "\r\n\r\n")
	}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("step4 write: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		t.Fatalf("step4 read: %v", err)
	}
	if isEcho {
		t.Logf("step4 ECHO 回显前64字节: % x", buf[:minInt(n, 64)])
		pad := make([]byte, minInt(n, len(req)))
		for i := range pad {
			pad[i] = buf[i] ^ req[i]
		}
		t.Logf("step4 ECHO 密钥流前%d字节: % x", len(pad), pad)
		if key, err := base64.StdEncoding.DecodeString(cfg.XorBytes); err == nil {
			t.Logf("step4 base64解密钥: % x (len=%d)", key, len(key))
		}
		return
	}
	if isDNS {
		// 应答结构: [id 2B=1234][flags 2B][qd/an/ns/ar 6B][question 原样回显 29B][answer...]
		// 用 id(0-1) + question 回显两段已知明文推导密钥流
		t.Logf("step4 DNS 密文前64字节: % x", buf[:minInt(n, 64)])
		type padAt struct {
			p   int
			val byte
		}
		var pads []padAt
		for pos, want := range map[int]byte{0: 0x00, 1: byte(len(req) - 2), 2: 0x12, 3: 0x34} {
			if pos < n {
				pads = append(pads, padAt{pos, buf[pos] ^ want})
			}
		}
		for i, b := range req[14:] { // question 段回显（2B长度 + 12B DNS 头之后）
			pos := 14 + i
			if pos < n {
				pads = append(pads, padAt{pos, buf[pos] ^ b})
			}
		}
		sort.Slice(pads, func(i, j int) bool { return pads[i].p < pads[j].p })
		var sb strings.Builder
		for _, pa := range pads {
			sb.WriteString(fmt.Sprintf("[%d]%02x(%%%d=%d) ", pa.p, pa.val, pa.p, pa.p%4))
		}
		t.Logf("step4 DNS 密钥流: %s", sb.String())
		if key, err := base64.StdEncoding.DecodeString(cfg.XorBytes); err == nil {
			t.Logf("step4 base64解密钥: % x (len=%d)", key, len(key))
		}
		return
	}
	printable := buf[:n]
	for i, b := range printable {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			printable[i] = '.'
		}
	}
	t.Logf("step4 OK: TCP CONNECT %s relayed, first %d bytes: %.80q", target, n, printable)

	// 用已知明文前缀推导真实 XOR 密钥流，并与候选密钥对比
	if n > 0 {
		expected := []byte("HTTP/1.1 400 Bad Request\r\nServer: cloudflare\r\nDate: ")
		m := len(expected)
		if n < m {
			m = n
		}
		if n < 48 {
			t.Logf("step4c 原始前%d字节: % x", n, buf[:n])
		} else {
			t.Logf("step4c 原始前48字节: % x", buf[:48])
		}
		if len(expected) > m {
			expected = expected[:m]
		}
		pad := make([]byte, m)
		for i := 0; i < m; i++ {
			pad[i] = buf[i] ^ expected[i]
		}
		t.Logf("step4c 密钥流前%d字节: % x", m, pad)
		if key, err := base64.StdEncoding.DecodeString(cfg.XorBytes); err == nil {
			t.Logf("step4c base64解密钥: % x (len=%d)", key, len(key))
		}
	}

	// 5. UDP ASSOCIATE（注意：关联走 node_list 端口，与 TCP 端口不同）
	udpClient := &Client{
		Node: cfg.EntryNode(),
		Ver:  cfg.Ver,
		Sess: &Session{HeyboxID: id, SessionID: cfg.SessionID, Username: pkey, AESKey: decodeKey(cfg.AESKey)},
	}
	assoc, err := udpClient.UDPAssociate(ctx)
	if err != nil {
		t.Fatalf("step5 UDPAssociate: %v", err)
	}
	defer assoc.Close()
	t.Logf("step5 OK: UDP relay=%s (BND 私网已替换为节点入口)", assoc.Relay)

	// step5b: 经中继发一个真实 DNS 查询（8.8.8.8:53），验证 UDP 数据面
	if os.Getenv("HEYBOX_SKIP_UDP_DATA") == "" {
		// dig nintendo.com A 的最小查询包
		q := []byte{
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			8, 'n', 'i', 'n', 't', 'e', 'n', 'd', 'o', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
		}
		if err := assoc.SendTo(q, "8.8.8.8:53"); err != nil {
			t.Fatalf("step5b SendTo: %v", err)
		}
		_ = assoc.SetReadDeadline(time.Now().Add(10 * time.Second))
		data, from, err := assoc.ReadFrom()
		if err != nil {
			t.Fatalf("step5b ReadFrom: %v", err)
		}
		t.Logf("step5b OK: UDP DNS 经中继往返, from=%s len=%d resp[2:4]=%02x%02x (DNS flags)", from, len(data), data[2], data[3])
	}

	fmt.Fprintln(os.Stderr, "LIVE PROBE ALL GREEN")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func respRep(r *SocksResponse) byte {
	if r == nil {
		return 0xFF
	}
	return r.Rep
}

func decodeKey(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}
