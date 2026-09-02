package heybox

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// UDP 头 flags 位。
const (
	UDPFlagSeq       byte = 0x01 // 携带递增序号（marker ≥1000）
	UDPFlagHasID     byte = 0x02 // 携带附加 ID
	UDPFlagBigHeader byte = 0x04 // 大头模式：追加 [heybox_id u64 BE][session_id u32 BE]
)

// UDPHeader 对应原版 socks.UDPHeader：
//
//	+0 u16  marker（BE；启用序号时为 ≥1000 递增计数）
//	+2 u8   flags
//	+4 u32  session_id（BE）
//	+8 u64  heyboxID（flags&0x04 时有效）
//	+0x10 u32 sessionID（flags&0x04 时有效）
type UDPHeader struct {
	Marker    uint16
	Flags     byte
	V32       uint32
	HeyboxID  int64
	SessionID uint32
}

// Size 返回头部长度：flags&0x04 时 19 字节，否则 7 字节。
func (h *UDPHeader) Size() int {
	if h.Flags&UDPFlagBigHeader != 0 {
		return 19
	}
	return 7
}

// Encode 客户端→服务器方向头部编码。
func (h *UDPHeader) Encode() []byte {
	b := make([]byte, h.Size())
	binary.BigEndian.PutUint16(b[0:2], h.Marker)
	b[2] = h.Flags
	binary.BigEndian.PutUint32(b[3:7], h.V32)
	if h.Flags&UDPFlagBigHeader != 0 {
		binary.BigEndian.PutUint64(b[7:15], uint64(h.HeyboxID))
		binary.BigEndian.PutUint32(b[15:19], h.SessionID)
	}
	return b
}

// AppendUDPHeader 复刻 socks.WriteUdpHeader @0x8DC640：
// 在 payload 前插入 [marker u16 BE][flags u8][session_id u32 BE] + AddrN(addr)。
func AppendUDPHeader(b []byte, addr string, sessID uint32, marker uint16, flags byte) ([]byte, error) {
	a, err := NewAddr(addr)
	if err != nil {
		return nil, err
	}
	ab, err := a.EncodeToBytes()
	if err != nil {
		return nil, err
	}
	hdr := []byte{0, 0, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(hdr[0:2], marker)
	binary.BigEndian.PutUint32(hdr[3:7], sessID)
	out := make([]byte, 0, len(b)+len(hdr)+len(ab))
	out = append(out, hdr...)
	out = append(out, ab...)
	out = append(out, b...)
	return out, nil
}

// UDPDatagram 完整 UDP 数据报（头部 + 目标地址 + 载荷）。
type UDPDatagram struct {
	Header UDPHeader
	Addr   *AddrN
	Data   []byte
}

// ParseGostUDPDatagram 解析服务器→客户端方向的数据报
// （对应 socks.ReadGostUDPDatagramFromBytes @0x8DB940）：
//
//	常规:   [RSV u16][flags u8][AddrN][payload]                     头 3 字节
//	flags&4:[RSV u16][flags u8][heybox_id u64 BE][session_id u32 BE][AddrN][payload] 头 15 字节
func ParseGostUDPDatagram(b []byte) (*UDPDatagram, error) {
	if len(b) < 10 {
		return nil, errors.New("heybox: datagram too short (<10)")
	}
	d := &UDPDatagram{}
	d.Header.Marker = binary.BigEndian.Uint16(b[0:2])
	d.Header.Flags = b[2]
	off := 3
	if b[2]&UDPFlagBigHeader != 0 {
		if len(b) < 0x16 {
			return nil, errors.New("heybox: datagram too short (<22)")
		}
		d.Header.HeyboxID = int64(binary.BigEndian.Uint64(b[3:11]))
		d.Header.SessionID = binary.BigEndian.Uint32(b[11:15])
		off = 15
	}
	a := &AddrN{}
	n, err := a.Decode(b[off:])
	if err != nil {
		return nil, err
	}
	d.Addr = a
	d.Data = b[off+n:]
	return d, nil
}

// UDPAssociation 维护一次 UDP ASSOCIATE 的全部资源：
// 保活 TCP 连接、UDP socket 与中继端点。
type UDPAssociation struct {
	Conn      *net.TCPConn // 关联用的 TCP 连接（关联租约的载体，保持打开）
	Relay     *net.UDPAddr // 中继端点（应答 BND.PORT；私网地址已替换为节点入口 IP）
	UseMarker bool         // 启用递增序号（flags|=0x01，marker 从 1000 起）

	rawConn net.Conn
	pc      *net.UDPConn
	sessID  uint32
	mu      sync.Mutex
	marker  uint16
}

// SendTo 通过中继向 dst 发送一个 UDP 载荷。
func (a *UDPAssociation) SendTo(payload []byte, dst string) error {
	var marker uint16
	var flags byte
	if a.UseMarker {
		a.mu.Lock()
		if a.marker < 1000 {
			a.marker = 1000
		}
		marker = a.marker
		a.marker++
		a.mu.Unlock()
		flags |= UDPFlagSeq
	}
	pkt, err := AppendUDPHeader(payload, dst, a.sessID, marker, flags)
	if err != nil {
		return err
	}
	_, err = a.pc.WriteToUDP(pkt, a.Relay)
	return err
}

// ReadFrom 从中继接收一个数据报，返回载荷与来源地址。
func (a *UDPAssociation) ReadFrom() ([]byte, *AddrN, error) {
	buf := make([]byte, 65535)
	n, _, err := a.pc.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, err
	}
	d, err := ParseGostUDPDatagram(buf[:n])
	if err != nil {
		return nil, nil, fmt.Errorf("heybox: parse datagram: %w", err)
	}
	return d.Data, d.Addr, nil
}

// SetReadDeadline 设置中继接收超时。
func (a *UDPAssociation) SetReadDeadline(t time.Time) error {
	return a.pc.SetReadDeadline(t)
}

// Close 释放 UDP socket 与关联 TCP 连接。
func (a *UDPAssociation) Close() error {
	var firstErr error
	if a.pc != nil {
		if err := a.pc.Close(); err != nil {
			firstErr = err
		}
	}
	if a.rawConn != nil {
		if err := a.rawConn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// UDPAssociate 与节点完成 UDP ASSOCIATE 握手（子命令 03 02，flags=0x01，目标 0.0.0.0:0）。
//
// 中继地址处理：应答 BND.ADDR 常为私网地址（实测 10.x），公网不可达——
// 此时以节点入口 IP 替换、保留 BND.PORT（与 mihomo socks5 出站处理未指定 BND 的方式同理）。
func (c *Client) UDPAssociate(ctx context.Context) (*UDPAssociation, error) {
	conn, err := c.dialNode(ctx)
	if err != nil {
		return nil, err
	}
	tcpConn, _ := conn.(*net.TCPConn)
	req := &SocksRequest{
		Ver:   c.Ver,
		Cmd1:  CmdUDPAssoc1,
		Cmd2:  CmdUDPAssoc2,
		Flags: 0x01,
		Pwd:   PwdBase(c.Sess),
		User:  c.Sess.Username,
		Addr:  "", // 空地址 → 0.0.0.0:0
	}
	br := bufio.NewReader(conn)
	resp, err := c.handshake(ctx, conn, br, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	relay, err := net.ResolveUDPAddr("udp", resp.Addr.String())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("heybox: resolve relay addr: %w", err)
	}
	if ip := relay.IP; ip == nil || ip.IsUnspecified() || ip.IsPrivate() || ip.IsLoopback() {
		// BND 为私网/未指定地址：替换为节点入口 IP，保留 BND.PORT
		if host, _, splitErr := net.SplitHostPort(c.Node); splitErr == nil {
			relay.IP = net.ParseIP(host)
		}
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &UDPAssociation{
		Conn:      tcpConn,
		rawConn:   conn,
		Relay:     relay,
		pc:        pc,
		sessID:    uint32(c.Sess.SessionID),
		UseMarker: true,
	}, nil
}
