package heybox

import (
	"testing"
)

// hkey 黄金向量来自真实抓包（heybox_acc_go_flows），全部为后端生成的
// 混合大小写 nonce（hkey 与 query 使用同一 nonce）。算法经 Unicorn 直接
// 执行 PE 机器码交叉验证。
func TestGenerateHkeyGolden(t *testing.T) {
	vectors := []struct {
		path  string
		ts    int64
		nonce string
		want  string
	}{
		{"/proxy/pc_has_new_version/", 1788242898, "Z1545uTllxPxaFXQaEYKHvbkiskoL0gq", "0PU5A50"},
		{"/proxy/get_user_vip_info/", 1788242898, "GRtefS7H56tTlOMJd7ZoylJUzRSSnoMn", "5JJQT02"},
		{"/proxy/get_acc_message_has_new/", 1788242898, "DRgXiiQ7a3q4O99dXcVNIoxqRGt1l85U", "98XQ206"},
		{"/proxy/hardware/report/", 1788242898, "1k3aR19dDhqW3ASm6kZp9qzeDDu06EwS", "8EGQK46"},
		{"/proxy/used_game_list_for_pc/", 1788242898, "z1pQS3RyFQ9qXvayU6SjiQHkB8owKf2Y", "8223Y10"},
		{"/proxy/get_abroad_node_list/", 1788242908, "7damStJ2EEzu0QklUu31Kg3swVxh6llC", "38DQ494"},
		{"/proxy/proxy_node_list/", 1788242919, "3tH7tkscaF1bDI6ik0Ce785vQtEfbEMg", "CCTN682"},
	}
	for _, v := range vectors {
		if got := GenerateHkey(v.path, v.ts, v.nonce); got != v.want {
			t.Errorf("GenerateHkey(%q, %d, %q) = %q, want %q", v.path, v.ts, v.nonce, got, v.want)
		}
	}
}

func TestGenerateHkeyPathNormalization(t *testing.T) {
	// "?" 之后被截断；不以 "/" 结尾则补 "/"
	a := GenerateHkey("/proxy/x/?&acc_id=356", 100, "abc123")
	b := GenerateHkey("/proxy/x/", 100, "abc123")
	if a != b {
		t.Errorf("query string should be stripped: %q != %q", a, b)
	}
	c := GenerateHkey("/proxy/x", 100, "abc123")
	if c != b {
		t.Errorf("trailing slash should be appended: %q != %q", c, b)
	}
}

func TestGFMul(t *testing.T) {
	// GF(2^8) 乘法自检：gfMul3 = a*3, gfMul6 = a*6, gfX4 = a*0x14, gfXe = a*0x11
	for a := 0; a < 256; a++ {
		b := byte(a)
		if got, want := gfMul3(b), gfmulRef(b, 3); got != want {
			t.Fatalf("gfMul3(%d) = %d, want %d", a, got, want)
		}
		if got, want := gfMul6(b), gfmulRef(b, 6); got != want {
			t.Fatalf("gfMul6(%d) = %d, want %d", a, got, want)
		}
		if got, want := gfX4(b), gfmulRef(b, 0x14); got != want {
			t.Fatalf("gfX4(%d) = %d, want %d", a, got, want)
		}
		if got, want := gfXe(b), gfmulRef(b, 0x11); got != want {
			t.Fatalf("gfXe(%d) = %d, want %d", a, got, want)
		}
	}
}

// gfmulRefGF(2^8) 朴素倍加法参考实现。
func gfmulRef(a byte, k byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		if k&(1<<i) != 0 {
			r ^= gfmulPow2(a, i)
		}
	}
	return r
}

func gfmulPow2(a byte, n int) byte {
	for i := 0; i < n; i++ {
		a = gfXtime(a)
	}
	return a
}
