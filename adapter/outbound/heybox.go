package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/singledo"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/heybox"
)

// HeyboxOption 是 type: heybox 出站的配置。会话（session_id/密钥/端口）
// 由加速服务在 proxy_node_list 响应中原子下发，本出站惰性获取并缓存。
type HeyboxOption struct {
	BasicOption
	Name           string `proxy:"name"`
	HeyboxID       int64  `proxy:"heybox-id"`
	Pkey           string `proxy:"pkey"`
	AccID          int    `proxy:"acc-id"`
	GameID         int    `proxy:"game-id"`
	ServerRegion   int    `proxy:"server-region"`   // 大区 ID（acc_district_id）
	NodeName       string `proxy:"node-name"`       // 节点名（如 日本3）
	AccMode        int    `proxy:"acc-mode"`        // 默认 1
	TransportProto string `proxy:"transport-proto"` // 默认 udp
	ISP            string `proxy:"isp,omitempty"`
	APIBase        string `proxy:"api,omitempty"`       // accapi 地址覆盖
	NodeIP         string `proxy:"node-ip,omitempty"`   // 枚举阶段的入口 IP（仅展示/参考）
	EchoAddr       string `proxy:"echo-addr,omitempty"` // 入口 UDP 回声探测地址（ip:port，枚举下发）
	RTTAvg         int    `proxy:"rtt-avg,omitempty"`   // 枚举延迟参考值，<999 有效；DelayHint 兜底
}

// heyboxAPIRequestTimeout 是控制面会话拉取的独立超时。
const heyboxAPIRequestTimeout = 15 * time.Second

type Heybox struct {
	*Base
	option *HeyboxOption
	api    *heybox.APIClient

	mu     sync.Mutex
	cached *heybox.NodeConfig
	single *singledo.Single[*heybox.NodeConfig]
}

func NewHeybox(option HeyboxOption) (*Heybox, error) {
	if option.HeyboxID == 0 || option.Pkey == "" {
		return nil, fmt.Errorf("heybox %s: heybox-id/pkey required", option.Name)
	}
	if option.AccID == 0 {
		return nil, fmt.Errorf("heybox %s: acc-id required", option.Name)
	}
	addr := option.NodeName
	if option.NodeIP != "" {
		addr = option.NodeIP
	}
	hb := &Heybox{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Heybox,
			ProviderName: option.ProviderName,
			UDP:          true,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
		api:    heybox.NewAPIClient(option.HeyboxID, option.Pkey, option.ISP, option.APIBase),
		single: singledo.NewSingle[*heybox.NodeConfig](
			30 * time.Second, // 合并短时间内的并发会话拉取
		),
	}
	hb.dialer = option.NewDialer(hb.DialOptions())
	return hb, nil
}

// getSession 惰性获取会话配置（singleflight 合并并发），缓存直到失效。
// 控制面请求使用独立超时，不继承数据面 ctx 的 deadline。
func (h *Heybox) getSession(_ context.Context) (*heybox.NodeConfig, error) {
	v, err, _ := h.single.Do(func() (*heybox.NodeConfig, error) {
		h.mu.Lock()
		if h.cached != nil {
			h.mu.Unlock()
			return h.cached, nil
		}
		h.mu.Unlock()
		apiCtx, cancel := context.WithTimeout(context.Background(), heyboxAPIRequestTimeout)
		defer cancel()
		cfg, err := h.api.NodeConfig(apiCtx, heybox.NodeConfigParams{
			AccID:          h.option.AccID,
			GameID:         h.option.GameID,
			ServerRegion:   h.option.ServerRegion,
			NodeName:       h.option.NodeName,
			AccMode:        h.option.AccMode,
			TransportProto: h.option.TransportProto,
			ISP:            h.option.ISP,
		})
		if err != nil {
			return nil, err
		}
		h.mu.Lock()
		h.cached = cfg
		h.mu.Unlock()
		return cfg, nil
	})
	if err != nil {
		return nil, err
	}
	return v, nil
}

// invalidateSession 作废缓存的会话（自愈：连续失败时整会话重拉）。
func (h *Heybox) invalidateSession() {
	h.mu.Lock()
	h.cached = nil
	h.mu.Unlock()
	h.single.Reset()
}

// withSession 执行 fn(ctx, cfg)；失败时作废会话并重拉一次重试。
// 会话拉取使用独立的控制面 ctx：隧道拨号 ctx 的 deadline 属于数据面，不传染给 API 请求。
func (h *Heybox) withSession(ctx context.Context, fn func(cfg *heybox.NodeConfig) error) error {
	cfg, err := h.getSession(ctx)
	if err != nil {
		log.Debugln("[Heybox] %s fetch session: %v", h.name, err)
		return err
	}
	if err := fn(cfg); err != nil {
		var repErr *heybox.ReplyError
		if !errors.As(err, &repErr) {
			// 网络类错误（拨号/握手读超时）：会话大概率仍有效，不作废，
			// 避免无谓重拉会话触发服务端风控
			log.Debugln("[Heybox] %s attempt with session %d failed (network, keep session): %v", h.name, cfg.SessionID, err)
			return err
		}
		log.Debugln("[Heybox] %s attempt with session %d failed (rep=%d, refresh session): %v", h.name, cfg.SessionID, repErr.Rep, err)
		h.invalidateSession()
		// 会话级错误（服务端回收/账号互踢/会话失效）：重拉一次
		cfg2, err2 := h.getSession(context.Background())
		if err2 != nil {
			return err
		}
		log.Debugln("[Heybox] %s retry with new session %d", h.name, cfg2.SessionID)
		if err2 := fn(cfg2); err2 != nil {
			return err2
		}
	}
	return nil
}

// resolveAddress 把 host:port 中的域名解析为 IP（节点拒收域名目标，REP=0x0a）。
func (h *Heybox) resolveAddress(ctx context.Context, address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	if ip := net.ParseIP(host); ip != nil {
		return address
	}
	ip, err := resolveIPWithResolver(ctx, host, h.prefer, resolver.DefaultResolver)
	if err != nil {
		return address // 解析失败原样发送（与原版行为一致）
	}
	return net.JoinHostPort(ip.String(), port)
}

func (h *Heybox) newClient(node string, cfg *heybox.NodeConfig) *heybox.Client {
	return &heybox.Client{
		Node: node,
		Ver:  cfg.Ver,
		Sess: &heybox.Session{
			HeyboxID:  h.option.HeyboxID,
			SessionID: cfg.SessionID,
			Username:  h.option.Pkey,
			AESKey:    decodeAESKey(cfg.AESKey),
		},
		XORKey: cfg.XORKey(), // TCP 数据通道循环 XOR（握手帧不参与）
		DialNode: func(ctx context.Context, node string) (net.Conn, error) {
			return h.dialer.DialContext(ctx, "tcp", node)
		},
	}
}

func decodeAESKey(s string) []byte {
	if s == "" {
		return nil
	}
	// base64（标准编码）；无效则按原文字节使用（16 字节 ASCII 密钥）
	if k, err := base64.StdEncoding.DecodeString(s); err == nil && len(k) > 0 {
		return k
	}
	return []byte(s)
}

// StreamConnContext implements C.ProxyAdapter
func (h *Heybox) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	return nil, C.ErrNotSupport
}

// DialContext implements C.ProxyAdapter — TCP CONNECT（走 tcp_node_list 独立端口）。
func (h *Heybox) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	target := h.resolveAddress(ctx, metadata.RemoteAddress())
	var conn net.Conn
	err = h.withSession(ctx, func(cfg *heybox.NodeConfig) error {
		node := cfg.TCPNode()
		if node == "" {
			node = cfg.EntryNode()
		}
		client := h.newClient(node, cfg)
		c, _, e := client.DialTCP(ctx, target)
		if e != nil {
			return e
		}
		conn = c
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("heybox %s: dial %s: %w", h.name, target, err)
	}
	return NewConn(conn, h), nil
}

// ListenPacketContext implements C.ProxyAdapter — UDP ASSOCIATE（走 node_list 入口端口）。
func (h *Heybox) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = h.ResolveUDP(ctx, metadata); err != nil {
		return nil, fmt.Errorf("heybox %s: resolve udp: %w", h.name, err)
	}
	var assoc *heybox.UDPAssociation
	err = h.withSession(ctx, func(cfg *heybox.NodeConfig) error {
		client := h.newClient(cfg.EntryNode(), cfg)
		a, e := client.UDPAssociate(ctx)
		if e != nil {
			return e
		}
		assoc = a
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("heybox %s: udp associate: %w", h.name, err)
	}
	return NewPacketConn(&heyboxPacketConn{assoc: assoc}, h), nil
}

// heyboxPacketConn 把 UDP 关联适配为 mihomo 的 PacketConn：
// 每个出站包加 gost 风格头（marker/flags/session_id/AddrN），入站包反向解析。
type heyboxPacketConn struct {
	assoc *heybox.UDPAssociation
}

func (c *heyboxPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	dst := addr.String()
	if host, port, err := net.SplitHostPort(dst); err == nil && net.ParseIP(host) == nil {
		// 节点拒收域名：尽力解析为 IP
		if ip, err := resolver.ResolveIP(context.Background(), host); err == nil {
			dst = net.JoinHostPort(ip.String(), port)
		}
	}
	if err := c.assoc.SendTo(b, dst); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *heyboxPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	data, from, err := c.assoc.ReadFrom()
	if err != nil {
		return 0, nil, err
	}
	n := copy(b, data)
	udpAddr := &net.UDPAddr{IP: net.ParseIP(from.Host), Port: int(from.Port)}
	return n, udpAddr, nil
}

func (c *heyboxPacketConn) Close() error {
	return c.assoc.Close()

}

func (c *heyboxPacketConn) LocalAddr() net.Addr {
	if c.assoc.Relay != nil {
		return c.assoc.Relay
	}
	return &net.UDPAddr{}
}

func (c *heyboxPacketConn) SetDeadline(t time.Time) error      { return errNoDeadline }
func (c *heyboxPacketConn) SetReadDeadline(t time.Time) error  { return errNoDeadline }
func (c *heyboxPacketConn) SetWriteDeadline(t time.Time) error { return errNoDeadline }

var errNoDeadline = fmt.Errorf("heybox: deadline not supported")

// DelayHint implements C.DelayHinter — 零拨号探活：优先对节点入口 UDP 回声
// 端口实测 RTT（原版同款机制，无会话副作用）；失败时以枚举延迟 rtt_avg
// （<999 有效）兜底；两者皆不可用才报不可达。健康检查/url-test/面板测速均复用此路径。
func (h *Heybox) DelayHint(ctx context.Context) (uint16, error) {
	if h.option.EchoAddr != "" {
		hintCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if rtt, err := heybox.UDPEchoPing(hintCtx, h.option.EchoAddr, 1500*time.Millisecond); err == nil {
			cancel()
			return rtt, nil
		} else {
			log.Debugln("[Heybox] %s echo ping %s: %v", h.name, h.option.EchoAddr, err)
		}
		cancel()
	}
	if h.option.RTTAvg > 0 && h.option.RTTAvg < 999 {
		return uint16(h.option.RTTAvg), nil
	}
	return 0, fmt.Errorf("heybox %s: node unreachable (echo failed, rtt_avg=%d)", h.name, h.option.RTTAvg)
}

// ProxyInfo implements C.ProxyAdapter
func (h *Heybox) ProxyInfo() C.ProxyInfo {
	info := h.Base.ProxyInfo()
	info.DialerProxy = h.option.DialerProxy
	return info
}
