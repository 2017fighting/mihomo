package heybox

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// 请求体子命令前两字节（第三字节为路由 flags）。
const (
	CmdTCPConnect1 byte = 0x01 // + 0x02：TCP CONNECT
	CmdTCPConnect2 byte = 0x02
	CmdUDPAssoc1   byte = 0x03 // + 0x02：UDP ASSOCIATE（抓包验证 cmd=03 02 flags=01）
	CmdUDPAssoc2   byte = 0x02
	CmdUoTAssoc1   byte = 0xF4 // + 0x00：game_use_tcp 开启时的关联变体（未使用）
	CmdUoTAssoc2   byte = 0x00
)

// 路由 flags 位（HandleCommon 中逐位 OR 累积，默认 0x03）。
const (
	FlagSeq        byte = 0x01 // UDP 包启用递增序号
	FlagBigHeader  byte = 0x04 // UDP 大头模式 / IPv6 头
	FlagRouteProxy byte = 0x02 // 目标端口在允许列表/走代理
	FlagSpecial    byte = 0x04 // 特殊路由（YY IP 等）
	DefaultFlags   byte = 0x03
)

// Session 携带握手所需会话身份（原版为 socks 包全局变量）。
type Session struct {
	HeyboxID  int64  // 登录用户 ID
	SessionID int32  // 会话 ID（配置下发）
	Username  string // 登录 pkey
	AESKey    []byte // VER>=10 时必填：服务器下发 aes_key（16 字节）
}

// PwdBase 构造握手密码串基础部分 "%d:%d"（session_id:heybox_id）。
func PwdBase(s *Session) string {
	return fmt.Sprintf("%d:%d", s.SessionID, s.HeyboxID)
}

// SocksRequest 对应原版 socks.NewSocksRequest。
type SocksRequest struct {
	Ver    byte
	Cmd1   byte
	Cmd2   byte
	Flags  byte
	Pwd    string
	User   string
	Addr   string // 目标 "host:port"；UDP ASSOCIATE 传 ""
	Random int32
}

// WriteTo 组帧并写出，复刻 (*NewSocksRequest).Write @0x8D6600：
//
//	VER<9:  [Ver][长度=0x0000][body]（明文，长度占位为零）
//	VER=9:  [0x09][ctLen u16 BE][Base64(AES-128-CBC(KeyVer9, IV=key, PKCS7(body)))]
//	VER≥10: [Ver][heybox_id u64 BE][session_id u32 BE][ctLen u16 BE][Base64(AES(...AESKey...))]
func (r *SocksRequest) WriteTo(w io.Writer, s *Session) error {
	buf := make([]byte, 0, 0x400)
	buf = append(buf, r.Ver)
	if r.Ver >= 0x0A {
		var b8 [8]byte
		binary.BigEndian.PutUint64(b8[:], uint64(s.HeyboxID))
		buf = append(buf, b8[:]...)
		var b4 [4]byte
		binary.BigEndian.PutUint32(b4[:], uint32(s.SessionID))
		buf = append(buf, b4[:]...)
	}
	lenOff := len(buf)
	buf = append(buf, 0, 0)
	addrStart := len(buf)

	buf = append(buf, r.Cmd1, r.Cmd2, r.Flags)

	_, rnd := generateHandshakeRandom()
	r.Random = rnd
	pwd := r.Pwd + fmt.Sprintf(":%d", rnd)
	if len(pwd) > 0xFF || len(r.User) > 0xFF {
		return errors.New("heybox: pwd/user exceeds 255 bytes")
	}
	buf = append(buf, byte(len(pwd)))
	buf = append(buf, pwd...)
	buf = append(buf, byte(len(r.User)))
	buf = append(buf, r.User...)

	addr, err := NewAddr(r.Addr)
	if err != nil {
		return err
	}
	ab, err := addr.EncodeToBytes()
	if err != nil {
		return err
	}
	buf = append(buf, ab...)

	var key []byte
	switch {
	case r.Ver == 9:
		key = []byte(KeyVer9)
	case r.Ver >= 0x0A:
		if len(s.AESKey) != 16 {
			return errors.New("heybox: VER>=10 requires 16-byte aes_key")
		}
		key = s.AESKey
	default:
		_, err = w.Write(buf)
		return err
	}
	ct, err := EncryptAES(key, buf[addrStart:])
	if err != nil {
		return err
	}
	if len(ct) > 0xFFFF {
		return errors.New("heybox: ciphertext exceeds 65535 bytes")
	}
	buf = buf[:addrStart]
	binary.BigEndian.PutUint16(buf[lenOff:lenOff+2], uint16(len(ct)))
	buf = append(buf, ct...)
	_, err = w.Write(buf)
	return err
}

// SocksResponse 对应原版 socks.NewSocksResponse。
type SocksResponse struct {
	Rep  byte   // 0=成功，0x0A=特殊状态，其余为错误码
	Addr *AddrN // BND.ADDR/BND.PORT（UDP ASSOCIATE 时为中继端点）
}

// ReplyError 表示服务器应答非成功状态。
type ReplyError struct {
	Rep byte
}

func (e *ReplyError) Error() string {
	return fmt.Sprintf("heybox: server reply REP=%d (want 0)", e.Rep)
}

// ReadReply 读取并解析应答帧：[b0][REP u8][b2][ATYP u8][BND.ADDR][BND.PORT u16 BE]。
// 采用精确读取（逐段 ReadFull），应答与后续数据同 TCP 段到达时多余字节保留在 br 中。
func ReadReply(r io.Reader) (*SocksResponse, error) {
	frame := make([]byte, 4, 22)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, err
	}
	readN := func(n int) error {
		old := len(frame)
		frame = append(frame, make([]byte, n)...)
		_, err := io.ReadFull(r, frame[old:])
		return err
	}
	switch frame[3] {
	case AtypIPv4:
		if err := readN(6); err != nil {
			return nil, err
		}
	case AtypDomain:
		if err := readN(1); err != nil {
			return nil, err
		}
		if err := readN(int(frame[4]) + 2); err != nil {
			return nil, err
		}
	case AtypIPv6:
		if err := readN(18); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("heybox: reply with unknown ATYP %d", frame[3])
	}
	addr := &AddrN{}
	if _, err := addr.Decode(frame[3:]); err != nil {
		return nil, err
	}
	return &SocksResponse{Rep: frame[1], Addr: addr}, nil
}

// bufferedConn 将握手阶段 bufio.Reader 中残留的字节透传给后续读取。
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.br.Read(p) }

// Client 是与加速节点握手的客户端。Node 由 DialNode 返回的连接承载，
// 便于 mihomo 出站经 dialer（接口/路由标记）建立到节点的连接。
type Client struct {
	Node string // 节点地址 host:port（node_list 中选出的入口）
	Ver  byte   // target_socks_version
	Sess *Session
	// Flags 为请求路由 flags，零值时使用 DefaultFlags(0x03)。
	Flags byte
	// DialNode 建立到节点的 TCP 连接；nil 时用 net.Dialer 直连。
	DialNode func(ctx context.Context, node string) (net.Conn, error)
	// DialTimeout 为连节点超时，零值 2s（原版 2s）。
	DialTimeout time.Duration
	// HandshakeTimeout 为读应答超时，零值 10s（原版 10s）。
	HandshakeTimeout time.Duration
	// XORKey 为 TCP 数据通道的循环 XOR 密钥（会话配置 xor_bytes 的 base64
	// 解码值）。非空时 DialTCP 返回的连接在握手后自动套上双向 XOR 层
	//（原版 Socks5EncrptConn，在线实测验证）。为空则返回裸连接。
	XORKey []byte
}

func (c *Client) flags() byte {
	if c.Flags == 0 {
		return DefaultFlags
	}
	return c.Flags
}

func (c *Client) dialTimeout() time.Duration {
	if c.DialTimeout == 0 {
		return 2 * time.Second
	}
	return c.DialTimeout
}

func (c *Client) handshakeTimeout() time.Duration {
	if c.HandshakeTimeout == 0 {
		return 10 * time.Second
	}
	return c.HandshakeTimeout
}

func (c *Client) dialNode(ctx context.Context) (net.Conn, error) {
	if c.Node == "" {
		return nil, errors.New("heybox: node address is empty")
	}
	if c.DialNode != nil {
		return c.DialNode(ctx, c.Node)
	}
	var d net.Dialer
	if c.dialTimeout() > 0 {
		d.Timeout = c.dialTimeout()
	}
	return d.DialContext(ctx, "tcp", c.Node)
}

func (c *Client) handshake(ctx context.Context, conn net.Conn, br *bufio.Reader, req *SocksRequest) (*SocksResponse, error) {
	if err := req.WriteTo(conn, c.Sess); err != nil {
		return nil, fmt.Errorf("heybox: write request: %w", err)
	}
	deadline := time.Now().Add(c.handshakeTimeout())
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	resp, err := ReadReply(br)
	if err != nil {
		return nil, fmt.Errorf("heybox: read reply: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	if resp.Rep != 0 {
		return resp, &ReplyError{Rep: resp.Rep}
	}
	return resp, nil
}

// resolveToIP 尽力把 host:port 解析为 IP:port（原版行为）；失败时原样返回。
// 真实节点只接受 IP 目标（ATYP=3 域名会被拒绝，实测 REP=0x0a）。
func resolveToIP(address string) string {
	ta, err := net.ResolveTCPAddr("tcp", address)
	if err != nil || ta.IP == nil {
		return address
	}
	return ta.String()
}

// DialTCP 与节点完成 TCP CONNECT 握手（子命令 01 02），成功后 conn 即为
// 通往目标地址的裸转发通道。TCP 走 tcp_node_list 的独立端口（如 5085）。
func (c *Client) DialTCP(ctx context.Context, address string) (net.Conn, *SocksResponse, error) {
	conn, err := c.dialNode(ctx)
	if err != nil {
		return nil, nil, err
	}
	req := &SocksRequest{
		Ver:   c.Ver,
		Cmd1:  CmdTCPConnect1,
		Cmd2:  CmdTCPConnect2,
		Flags: c.flags(),
		Pwd:   PwdBase(c.Sess),
		User:  c.Sess.Username,
		Addr:  resolveToIP(address),
	}
	br := bufio.NewReader(conn)
	resp, err := c.handshake(ctx, conn, br, req)
	if err != nil {
		conn.Close()
		return nil, resp, err
	}
	// 握手成功后，数据通道进入 XOR 模式（握手帧不 XOR，见 xor.go）
	return newXORConn(&bufferedConn{Conn: conn, br: br}, c.XORKey), resp, nil
}
