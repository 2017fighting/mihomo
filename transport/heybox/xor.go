package heybox

import "net"

// xorConn 是 TCP 数据通道的循环 XOR 层（对应原版 socks.Socks5EncrptConn
// Write @0x8E1680 / Read @0x8E1880，在线实测验证，见 heybox_acc PROTOCOL.md §13）。
//
// 规则：
//   - 仅作用于**握手成功后**的数据通道；握手帧（AES+base64）本身不 XOR
//   - key = 会话配置 xor_bytes 的 base64 解码值（实测 4 字节，随会话轮换）
//   - 双向独立：发送流与接收流各自从位置 0 开始计数（原版 Write 用 +0x28、
//     Read 用 +0x30 两个独立计数器，全双工交错安全）
//   - UDP 中继不走此层（实测明文）
type xorConn struct {
	net.Conn
	key  []byte
	wPos int // 发送流位置（原版偏移 +0x28）
	rPos int // 接收流位置（原版偏移 +0x30）
}

// newXORConn 用 key 包装 conn；key 为空时原样返回。
func newXORConn(conn net.Conn, key []byte) net.Conn {
	if len(key) == 0 {
		return conn
	}
	return &xorConn{Conn: conn, key: append([]byte(nil), key...)}
}

func (c *xorConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	for i := 0; i < n; i++ {
		p[i] ^= c.key[c.rPos%len(c.key)]
		c.rPos++
	}
	return n, err
}

func (c *xorConn) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	for i, b := range p {
		buf[i] = b ^ c.key[c.wPos%len(c.key)]
		c.wPos++
	}
	return c.Conn.Write(buf)
}
