package heybox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

// 地址类型（RFC1928 ATYP 语义，IPv6 用 4）。
const (
	AtypIPv4   byte = 0x01
	AtypDomain byte = 0x03
	AtypIPv6   byte = 0x04
)

var (
	errShortBuffer = errors.New("heybox: short buffer")
	errBadAddr     = errors.New("heybox: bad address")
)

// AddrN 对应原版 socks.AddrN。线上编码：[type u8][地址][端口 u16 BE]：
//
//	type=1: [1][4 字节 IPv4][port]         共 7 字节
//	type=3: [3][1 字节域长][域名][port]    共 域长+4 字节
//	type=4: [4][16 字节 IPv6][port]        共 19 字节
type AddrN struct {
	Type byte
	Host string
	Port uint16
}

// NewAddr 解析 "host:port"。IPv4→type1，IPv6→type4，其余→type3(域名)。
// 空字符串回退为 0.0.0.0:0（UDP ASSOCIATE 语义，原版 Encode 默认分支）。
func NewAddr(address string) (*AddrN, error) {
	if address == "" {
		return &AddrN{Type: AtypIPv4, Host: "0.0.0.0", Port: 0}, nil
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", errBadAddr, address)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: port %q", errBadAddr, portStr)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return &AddrN{Type: AtypIPv4, Host: host, Port: uint16(port)}, nil
		}
		return &AddrN{Type: AtypIPv6, Host: host, Port: uint16(port)}, nil
	}
	return &AddrN{Type: AtypDomain, Host: host, Port: uint16(port)}, nil
}

// Size 返回 Encode 所需字节数。
func (a *AddrN) Size() int {
	switch a.Type {
	case AtypIPv4:
		return 7
	case AtypDomain:
		return len(a.Host) + 4
	case AtypIPv6:
		return 19
	default:
		return 10
	}
}

// Encode 将地址编码进 b，返回写入字节数。未知类型回退为 [1][0.0.0.0][port]。
func (a *AddrN) Encode(b []byte) (int, error) {
	if len(b) < a.Size() {
		return 0, errShortBuffer
	}
	n := 0
	switch a.Type {
	case AtypIPv4:
		ip := net.ParseIP(a.Host)
		if ip == nil || ip.To4() == nil {
			return 0, fmt.Errorf("%w: not IPv4: %q", errBadAddr, a.Host)
		}
		b[0] = AtypIPv4
		copy(b[1:5], ip.To4())
		n = 5
	case AtypDomain:
		if len(a.Host) > 255 {
			return 0, fmt.Errorf("%w: domain too long", errBadAddr)
		}
		b[0] = AtypDomain
		b[1] = byte(len(a.Host))
		n = copy(b[2:], a.Host) + 2
	case AtypIPv6:
		ip := net.ParseIP(a.Host)
		if ip == nil {
			return 0, fmt.Errorf("%w: not IPv6: %q", errBadAddr, a.Host)
		}
		b[0] = AtypIPv6
		copy(b[1:17], ip.To16())
		n = 17
	default:
		b[0] = AtypIPv4
		copy(b[1:5], net.IPv4zero.To4())
		n = 5
	}
	binary.BigEndian.PutUint16(b[n:], a.Port)
	return n + 2, nil
}

// EncodeToBytes 返回独立编码的字节串。
func (a *AddrN) EncodeToBytes() ([]byte, error) {
	b := make([]byte, a.Size())
	n, err := a.Encode(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}

// Decode 从 b 解析地址，返回消耗的字节数。
func (a *AddrN) Decode(b []byte) (int, error) {
	if len(b) < 2 {
		return 0, errShortBuffer
	}
	switch b[0] {
	case AtypIPv4:
		if len(b) < 7 {
			return 0, errShortBuffer
		}
		a.Type = AtypIPv4
		a.Host = net.IP(b[1:5]).String()
		a.Port = binary.BigEndian.Uint16(b[5:7])
		return 7, nil
	case AtypDomain:
		l := int(b[1])
		if len(b) < 4+l {
			return 0, errShortBuffer
		}
		a.Type = AtypDomain
		a.Host = string(b[2 : 2+l])
		a.Port = binary.BigEndian.Uint16(b[2+l : 4+l])
		return 4 + l, nil
	case AtypIPv6:
		if len(b) < 19 {
			return 0, errShortBuffer
		}
		a.Type = AtypIPv6
		a.Host = net.IP(b[1:17]).String()
		a.Port = binary.BigEndian.Uint16(b[17:19])
		return 19, nil
	default:
		return 0, fmt.Errorf("%w: unsupported ATYP %d", errBadAddr, b[0])
	}
}

// String 返回 "host:port" 形式。
func (a *AddrN) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}
