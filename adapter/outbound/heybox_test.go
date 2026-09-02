package outbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/heybox"
)

// --- mock 加速节点（对应 heybox_acc/goimpl/mocknode.py，VER=9） ---

type mockNode struct {
	tcpLn     net.Listener
	udpRelay  *net.UDPConn // UDP 中继（BND.PORT 指向这里）
	relayPort int
	xorKey    []byte // TCP 数据通道 XOR 密钥（由 mock accapi 下发同一密钥）
}

func startMockNode(t *testing.T) *mockNode {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	m := &mockNode{tcpLn: ln, udpRelay: uc, relayPort: uc.LocalAddr().(*net.UDPAddr).Port}
	go m.acceptTCP(t)
	go m.relayUDP(t)
	return m
}

func (m *mockNode) nodeAddr() string {
	return m.tcpLn.Addr().String()
}

func (m *mockNode) acceptTCP(t *testing.T) {
	for {
		conn, err := m.tcpLn.Accept()
		if err != nil {
			return
		}
		go m.handleTCP(t, conn)
	}
}

func (m *mockNode) handleTCP(t *testing.T, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	// 读 [VER=9][ctLen BE16][base64 ct]
	head := make([]byte, 3)
	if _, err := ioReadFull(conn, head); err != nil {
		return
	}
	ctLen := binary.BigEndian.Uint16(head[1:3])
	ct := make([]byte, ctLen)
	if _, err := ioReadFull(conn, ct); err != nil {
		return
	}
	body, err := heybox.DecryptAES([]byte(heybox.KeyVer9), ct)
	if err != nil {
		t.Logf("mock node: decrypt handshake: %v", err)
		return
	}
	if len(body) < 3 {
		return
	}
	var reply []byte
	switch body[0] {
	case heybox.CmdUDPAssoc1: // UDP ASSOCIATE → 回私网 BND（测试替换逻辑）
		port := m.relayPort
		reply = []byte{0, 0, 0, heybox.AtypIPv4, 10, 0, 0, 1, byte(port >> 8), byte(port)}
	default: // TCP CONNECT → 回 1.2.3.4:1080 后进入 echo 中继
		reply = []byte{0, 0, 0, heybox.AtypIPv4, 1, 2, 3, 4, 0x04, 0x38}
	}
	if _, err := conn.Write(reply); err != nil {
		return
	}
	if body[0] == heybox.CmdUDPAssoc1 {
		// 关联连接保持打开（租约），直到对端关闭
		buf := make([]byte, 64)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}
	// TCP：echo 中继（套上与真实节点一致的 XOR 数据通道层）
	relay := conn
	pos := 0 // 双向独立计数：echo 场景下发送/接收对称，各从 0 起
	rpos := 0
	if len(m.xorKey) > 0 {
		buf2 := make([]byte, 4096)
		for {
			n, err := conn.Read(buf2)
			if err != nil {
				return
			}
			for i := 0; i < n; i++ {
				buf2[i] ^= m.xorKey[rpos%len(m.xorKey)]
				rpos++
			}
			for i := 0; i < n; i++ {
				buf2[i] ^= m.xorKey[pos%len(m.xorKey)]
				pos++
			}
			if _, err := relay.Write(buf2[:n]); err != nil {
				return
			}
		}
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			return
		}
	}
}

func (m *mockNode) relayUDP(t *testing.T) {
	buf := make([]byte, 65535)
	for {
		n, from, err := m.udpRelay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// 客户端→服务器方向: [marker u16][flags u8][session_id u32][AddrN][payload]
		if n < 7 {
			continue
		}
		off := 7
		if buf[2]&heybox.UDPFlagBigHeader != 0 {
			off = 19
		}
		if n <= off {
			continue
		}
		addr := &heybox.AddrN{}
		addrLen, err := addr.Decode(buf[off:n])
		if err != nil {
			t.Logf("mock relay: parse addr: %v", err)
			continue
		}
		payload := buf[off+addrLen : n]
		// 服务器→客户端方向: [RSV u16][flags u8][AddrN][payload]，源地址 = 目标地址
		ab, err := addr.EncodeToBytes()
		if err != nil {
			continue
		}
		resp := make([]byte, 0, 3+len(ab)+5+len(payload))
		resp = append(resp, 0, 0, 0)
		resp = append(resp, ab...)
		resp = append(resp, []byte("ECHO:")...)
		resp = append(resp, payload...)
		_, _ = m.udpRelay.WriteToUDP(resp, from)
	}
}

func ioReadFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// --- mock accapi：proxy_node_list 返回指向 mock 节点的会话 ---

func startMockAccapi(t *testing.T, node *mockNode) *httptest.Server {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(node.nodeAddr())
	port, _ := strconv.Atoi(portStr)
	// 会话配置下发固定 xor_bytes；mock 节点与出站两侧使用同一密钥
	node.xorKey = []byte{0x33, 0x70, 0xa0, 0x66}
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/proxy_node_list/", func(w http.ResponseWriter, r *http.Request) {
		cfg := map[string]any{
			"session_id":           4155,
			"target_socks_version": 9,
			"xor_bytes":            base64.StdEncoding.EncodeToString(node.xorKey),
			"node_list":            []map[string]any{{"ip": host, "port": port}},
			"tcp_node_list":        []map[string]any{{"ip": host, "port": port}},
		}
		plain, _ := json.Marshal(cfg)
		ct, _ := heybox.EncryptAES([]byte(heybox.KeyConfigResult), plain)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"status":"ok","msg":"","result":%q}`, string(ct))))
	})
	return httptest.NewServer(mux)
}

// TestHeyboxE2E 覆盖完整链路：惰性会话(mock accapi) → 握手(VER=9) →
// TCP CONNECT echo 中继 / UDP ASSOCIATE + BND 私网替换 + gost 头往返。
func TestHeyboxE2E(t *testing.T) {
	node := startMockNode(t)
	defer node.tcpLn.Close()
	defer node.udpRelay.Close()
	api := startMockAccapi(t, node)
	defer api.Close()

	host, portStr, _ := net.SplitHostPort(node.nodeAddr())
	hb, err := NewHeybox(HeyboxOption{
		Name:         "hb-e2e",
		HeyboxID:     88800123,
		Pkey:         "pkeyABC",
		AccID:        356,
		GameID:       353,
		ServerRegion: 1001,
		NodeName:     "日本3",
		APIBase:      api.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// --- TCP CONNECT ---
	meta := &C.Metadata{
		NetWork: C.TCP,
		Host:    host,
		DstPort: uint16(80),
	}
	conn, err := hb.DialContext(ctx, meta)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	msg := []byte("ping-tcp")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("tcp write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := readFull(conn, got); err != nil {
		t.Fatalf("tcp read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("tcp echo = %q, want %q", got, msg)
	}

	// --- UDP ASSOCIATE（BND 为 10.0.0.1 私网，应替换为节点入口 127.0.0.1）---
	metaUDP := &C.Metadata{
		NetWork: C.UDP,
		DstIP:   netip.MustParseAddr("8.8.8.8"),
		Host:    "8.8.8.8",
		DstPort: 53,
	}
	pc, err := hb.ListenPacketContext(ctx, metaUDP)
	if err != nil {
		t.Fatalf("ListenPacketContext: %v", err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo([]byte("ping-udp"), &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	buf := make([]byte, 1024)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("udp read (relay unreachable if BND replace failed): %v", err)
	}
	if want := "ECHO:ping-udp"; string(buf[:n]) != want {
		t.Fatalf("udp echo = %q, want %q", buf[:n], want)
	}
	if from.String() != "8.8.8.8:53" {
		t.Fatalf("udp from = %s, want 8.8.8.8:53", from)
	}
	_ = portStr
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// TestHeyboxDelayHint 验证零拨号探活：UDP echo 实测优先、枚举延迟兜底。
func TestHeyboxDelayHint(t *testing.T) {
	// mock echo 服务器：回显收到的 8 字节
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = uc.WriteToUDP(buf[:n], from)
		}
	}()
	echoAddr := uc.LocalAddr().String()

	hb, err := NewHeybox(HeyboxOption{
		Name:     "hb-hint",
		HeyboxID: 1, Pkey: "x", AccID: 356,
		EchoAddr: echoAddr,
		RTTAvg:   45,
	})
	if err != nil {
		t.Fatal(err)
	}
	delay, err := hb.DelayHint(context.Background())
	if err != nil {
		t.Fatalf("DelayHint(echo): %v", err)
	}
	if delay == 0 || delay == 65535 {
		t.Fatalf("DelayHint(echo) = %d, want positive finite", delay)
	}

	// echo 不可达时回退 rtt_avg
	hb2, err := NewHeybox(HeyboxOption{
		Name:     "hb-hint2",
		HeyboxID: 1, Pkey: "x", AccID: 356,
		EchoAddr: "127.0.0.1:1", // 无人监听
		RTTAvg:   45,
	})
	if err != nil {
		t.Fatal(err)
	}
	delay2, err := hb2.DelayHint(context.Background())
	if err != nil {
		t.Fatalf("DelayHint(fallback): %v", err)
	}
	if delay2 != 45 {
		t.Fatalf("DelayHint(fallback) = %d, want 45", delay2)
	}

	// 两者皆不可用（rtt_avg=999 哨兵）→ 报不可达
	hb3, err := NewHeybox(HeyboxOption{
		Name:     "hb-hint3",
		HeyboxID: 1, Pkey: "x", AccID: 356,
		EchoAddr: "127.0.0.1:1",
		RTTAvg:   999,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hb3.DelayHint(context.Background()); err == nil {
		t.Fatal("DelayHint(rtt=999) should fail")
	}
}
