package heybox

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// UDPEchoPing 对节点入口的 UDP 回声端口（get_abroad_node_list 响应的 src 字段，
// 如 113.31.110.157:205）做 8 字节时间戳回显探测，返回往返延迟毫秒数。
//
// 与原版客户端的 RTT 探测机制相同（PROTOCOL.md §10.4）；服务端原样回显载荷，
// 不产生会话、不走 TCP。零会话副作用的探活/测速手段。
func UDPEchoPing(ctx context.Context, addr string, timeout time.Duration) (uint16, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return 0, fmt.Errorf("heybox echo dial %s: %w", addr, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixNano()))
	start := time.Now()
	if _, err := conn.Write(ts[:]); err != nil {
		return 0, fmt.Errorf("heybox echo write: %w", err)
	}

	var echo [8]byte
	if _, err := readFull8(conn, echo[:]); err != nil {
		return 0, fmt.Errorf("heybox echo read: %w", err)
	}
	rtt := time.Since(start)
	if echo != ts {
		// 回显不匹配仍视为可达（服务端可能改写载荷），仅以 RTT 为准
		_ = rtt
	}
	ms := rtt.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	if ms > 0xFFFF {
		ms = 0xFFFF
	}
	return uint16(ms), nil
}

func readFull8(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
