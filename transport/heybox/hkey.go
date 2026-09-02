package heybox

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// hkeyAlphabet 是 hkey 生成的固定字母表（rodata 字符串 @0xfce760）。
const hkeyAlphabet = "1234OABCDFG56789HJKMNPQRTX"

// GenerateHkey 复刻 heyboxacc.exe main.GetHkey @0x9daaa0。
//
// 算法已经 Unicorn 直接执行 PE 机器码与 23 个抓包黄金向量双向验证
// （详见 heybox_acc 仓库 PROTOCOL.md §13）：
//
//	s = path 去掉 "?" 之后的部分；不以 "/" 结尾则补 "/"
//	key = Base64.Std(s)
//	mac = HMAC-SHA1(key, BE64(nonce 中 '0'-'9' 字符数 + ts))
//	off = mac[19] & 0xf；u32 = BE32(mac[off:off+4]) & 0x7fffffff
//	table = "1234OABCDFG56789HJKMNPQRTX" + ToUpper(nonce)   ← 字母表在前
//	chars[i] = table[v % len(table)]，v 每次 /= len(table)，取 5 个字符
//	num = sum(GF 置换(chars[1:5])) % 100
//	hkey = chars[0:5] + fmt "%02d" num
//
// GF 置换为 GF(2^8)（多项式 0x1b）上的循环矩阵乘法，系数向量 (0x11, 0x14, 0x06, 0x03)。
func GenerateHkey(path string, ts int64, nonce string) string {
	s := path
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	if !strings.HasSuffix(s, "/") {
		s += "/"
	}

	digits := 0
	for i := 0; i < len(nonce); i++ {
		if nonce[i] >= '0' && nonce[i] <= '9' {
			digits++
		}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(int64(digits)+ts))

	key := []byte(base64.StdEncoding.EncodeToString([]byte(s)))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	off := int(sum[19] & 0xf)
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff

	table := hkeyAlphabet + strings.ToUpper(nonce)
	l := uint32(len(table))
	var chars [5]byte
	for i := range chars {
		chars[i] = table[v%l]
		v /= l
	}

	out := gfScramble([4]byte{chars[1], chars[2], chars[3], chars[4]})
	n := 0
	for _, b := range out {
		n += int(b)
	}
	return string(chars[:]) + fmt.Sprintf("%02d", n%100)
}

// GF(2^8) 运算（约减多项式 0x1b，与 AES 一致）。

func gfXtime(a byte) byte {
	b := a << 1
	if a&0x80 != 0 {
		b ^= 0x1b
	}
	return b
}

// gfMul6 = a·(4⊕2)。
func gfMul6(a byte) byte {
	m2 := gfXtime(a)
	return gfXtime(m2) ^ m2
}

// gfMul3 = a·(2⊕1)。
func gfMul3(a byte) byte {
	return gfXtime(a) ^ a
}

// gfX4 = a·0x14（原版 main.x4，四层 xtime 梯子）。
func gfX4(a byte) byte {
	t1 := gfXtime(a)
	t2 := gfXtime(t1)
	v := t2 ^ t1
	t3 := gfXtime(v)
	t4 := gfXtime(t3)
	return t4 ^ t3
}

// gfXe = a·0x11（原版 main.xe）。
func gfXe(a byte) byte {
	return gfX4(a) ^ gfMul6(a) ^ gfXtime(a) ^ a
}

// gfScramble 原版 main.xx：4 字节循环矩阵置换，系数 (0x11, 0x14, 0x06, 0x03)。
func gfScramble(b [4]byte) [4]byte {
	b0, b1, b2, b3 := b[0], b[1], b[2], b[3]
	return [4]byte{
		gfXe(b0) ^ gfX4(b1) ^ gfMul6(b2) ^ gfMul3(b3),
		gfMul3(b0) ^ gfXe(b1) ^ gfX4(b2) ^ gfMul6(b3),
		gfMul6(b0) ^ gfMul3(b1) ^ gfXe(b2) ^ gfX4(b3),
		gfX4(b0) ^ gfMul6(b1) ^ gfMul3(b2) ^ gfXe(b3),
	}
}
