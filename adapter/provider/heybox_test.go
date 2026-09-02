package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/heybox"
)

// mockAccapi 模拟 accapi 控制面：used_game_list + get_abroad_node_list，
// result 字段以 KeyConfigResult AES 加密。
func mockAccapi(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/used_game_list_for_pc/", func(w http.ResponseWriter, r *http.Request) {
		plain := `{"game_list":[{"acc_id":356,"game_id":353,"name":"Switch-通用","device_type":"Switch","current_mode_id":1,"acc_district":[{"acc_district_id":1001,"acc_district_name":"日本"},{"acc_district_id":1002,"acc_district_name":"中国香港"}]}]}`
		writeEncrypted(w, plain)
	})
	mux.HandleFunc("/proxy/get_abroad_node_list/", func(w http.ResponseWriter, r *http.Request) {
		var plain string
		switch r.URL.Query().Get("acc_district_id") {
		case "1001":
			plain = `{"node_list":[{"name":"日本3","dst_ip":"152.32.202.243","src":"113.31.110.157:205","first_hop_location":"上海联通","isp":"bgp","rtt_avg":45,"state":"空闲"},{"name":"日本9","dst_ip":"124.40.40.28","src":"113.31.109.185:205","first_hop_location":"上海联通","isp":"bgp","rtt_avg":48,"state":"空闲"}]}`
		default:
			plain = `{"node_list":[{"name":"香港130","dst_ip":"43.155.110.118","src":"114.132.165.45:205","first_hop_location":"广州联通","isp":"bgp","rtt_avg":21,"state":"空闲"}]}`
		}
		writeEncrypted(w, plain)
	})
	return httptest.NewServer(mux)
}

func writeEncrypted(w http.ResponseWriter, plain string) {
	ct, err := heybox.EncryptAES([]byte(heybox.KeyConfigResult), []byte(plain))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(fmt.Sprintf(`{"status":"ok","msg":"","result":%q}`, string(ct))))
}

func testTunnel() C.Tunnel {
	return nil // heybox 解析路径不使用 tunnel
}

func TestHeyboxVehicleRenderAndParse(t *testing.T) {
	srv := mockAccapi(t)
	defer srv.Close()

	schema := &heyboxProviderSchema{
		HeyboxID: 16651571,
		Pkey:     "TESTPKET",
		Games:    []int{356},
		APIBase:  srv.URL,
	}
	vehicle := NewHeyboxVehicle("hb-test", schema)

	buf, _, err := vehicle.Read(context.Background(), utils.HashType{})
	if err != nil {
		t.Fatalf("vehicle read: %v", err)
	}
	// 渲染结果不含凭证（可安全落盘）
	if want := []byte("TESTPKET"); containsBytes(buf, want) {
		t.Fatalf("rendered yaml contains pkey, must be credential-free:\n%s", buf)
	}
	for _, want := range []string{"Switch-通用-日本3", "Switch-通用-日本9", "Switch-通用-香港130"} {
		if !containsString(string(buf), want) {
			t.Fatalf("rendered yaml missing %q:\n%s", want, buf)
		}
	}

	parser, err := NewProxiesParser("hb-test", testTunnel(), "", "", "", "", overrideSchema{}, "")
	if err != nil {
		t.Fatalf("new parser: %v", err)
	}
	proxies, err := wrapHeyboxCredParser(parser, schema)(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(proxies) != 3 {
		t.Fatalf("expect 3 proxies, got %d", len(proxies))
	}
	names := map[string]bool{}
	for _, p := range proxies {
		names[p.Name()] = true
		if p.Type().String() != "Heybox" {
			t.Fatalf("proxy %s type = %s, want Heybox", p.Name(), p.Type())
		}
	}
	for _, want := range []string{"Switch-通用-日本3", "Switch-通用-日本9", "Switch-通用-香港130"} {
		if !names[want] {
			t.Fatalf("missing proxy %q, got %v", want, names)
		}
	}
}

func TestHeyboxVehicleGamesNotFound(t *testing.T) {
	srv := mockAccapi(t)
	defer srv.Close()

	schema := &heyboxProviderSchema{
		HeyboxID: 1,
		Pkey:     "x",
		Games:    []int{999999},
		APIBase:  srv.URL,
	}
	vehicle := NewHeyboxVehicle("hb-none", schema)
	if _, _, err := vehicle.Read(context.Background(), utils.HashType{}); err == nil {
		t.Fatal("expect error for unknown game id")
	}
}

func TestHeyboxVehicleFallbackToCache(t *testing.T) {
	// 先用活服务渲染并落盘，再换死服务验证回退
	live := mockAccapi(t)
	schema := &heyboxProviderSchema{HeyboxID: 1, Pkey: "x", Games: []int{356}, APIBase: live.URL}
	vehicle := NewHeyboxVehicle("hb-cache", schema)
	buf, _, err := vehicle.Read(context.Background(), utils.HashType{})
	if err != nil {
		t.Fatalf("live read: %v", err)
	}
	if err := vehicle.Write(buf); err != nil {
		t.Fatalf("write cache: %v", err)
	}
	live.Close()

	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer dead.Close()
	schema.APIBase = dead.URL
	buf2, _, err := vehicle.Read(context.Background(), utils.HashType{})
	if err != nil {
		t.Fatalf("fallback read should use cache, got err: %v", err)
	}
	if string(buf) != string(buf2) {
		t.Fatal("fallback content mismatch")
	}
}

// ParseProxyProvider 集成：type: heybox 的完整 provider 配置解析。
func TestParseProxyProviderHeybox(t *testing.T) {
	srv := mockAccapi(t)
	defer srv.Close()

	mapping := map[string]any{
		"type":      "heybox",
		"heybox-id": 16651571,
		"pkey":      "TESTPKET",
		"games":     []any{356},
		"api":       srv.URL,
		"health-check": map[string]any{
			"enable":   false,
			"url":      "http://conntest.nintendowifi.net/",
			"interval": 300,
		},
	}
	pd, err := ParseProxyProvider("hb-int", mapping, testTunnel())
	if err != nil {
		t.Fatalf("ParseProxyProvider: %v", err)
	}
	if err := pd.Initial(); err != nil {
		t.Fatalf("Initial: %v", err)
	}
	if pd.Count() != 3 {
		t.Fatalf("expect 3 proxies, got %d", pd.Count())
	}
	if pd.VehicleType().String() != "Heybox" {
		t.Fatalf("vehicle type = %s", pd.VehicleType())
	}
}

func containsString(s, sub string) bool { return strings.Contains(s, sub) }
func containsBytes(b, sub []byte) bool  { return strings.Contains(string(b), string(sub)) }
