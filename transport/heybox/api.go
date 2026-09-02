package heybox

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
)

// DefaultAPIBase 是小黑盒加速账号 API 的默认地址。
const DefaultAPIBase = "https://accapi.xiaoheihe.cn"

const (
	apiVersion        = "1.1.92" // 原版客户端版本号，部分接口校验
	apiUserAgentPC    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) heybox-acc-electron/1.1.63 Chrome/108.0.5359.215 Electron/22.3.27 Safari/537.36"
	apiRequestTimeout = 15 * time.Second
)

// District 是游戏可选的出口大区（日本/中国香港/北美/中国台湾…）。
type District struct {
	ID   int    `json:"acc_district_id"`
	Name string `json:"acc_district_name"`
}

// GameEntry 是 used_game_list 返回的游戏/设备条目。
type GameEntry struct {
	AccID         int        `json:"acc_id"`
	GameID        int        `json:"game_id"`
	Name          string     `json:"name"`
	DeviceType    string     `json:"device_type"` // Switch / PC
	CurrentModeID int        `json:"current_mode_id"`
	AccDistrict   []District `json:"acc_district"`
}

// AbroadNode 是 get_abroad_node_list 返回的节点枚举条目（无会话副作用）。
type AbroadNode struct {
	Name             string `json:"name"`               // 如 "日本3"、"香港130"
	DstIP            string `json:"dst_ip"`             // 海外出口 IP（仅展示用）
	Src              string `json:"src"`                // 国内入口 IP:udp_echo_port
	FirstHopLocation string `json:"first_hop_location"` // 如 "上海联通"
	ISP              string `json:"isp"`
	RTTAvg           int    `json:"rtt_avg"`
	State            string `json:"state"`
}

// NodeAddr 是会话配置中的节点连接地址（IP + 各角色端口）。
type NodeAddr struct {
	IP            string `json:"ip"`
	Port          int    `json:"port"` // UDP ASSOCIATE 端口（随会话轮换）
	TCPOnlinePort int    `json:"tcp_online_port"`
	PingPort      int    `json:"ping_port"`
	UDPEchoPort   int    `json:"udp_echo_port"`
}

// NodeConfig 是 proxy_node_list 响应解密后的会话配置（关键字段）。
type NodeConfig struct {
	SessionID   int32      `json:"session_id"`
	Ver         byte       `json:"target_socks_version"`
	AESKey      string     `json:"aes_key"` // base64，VER>=10 时使用
	GostVer     string     `json:"target_gost_version"`
	UDPOverTCP  bool       `json:"udp_over_tcp"`
	GameUseTCP  bool       `json:"game_use_tcp"`
	XorBytes    string     `json:"xor_bytes"`     // base64，TCP 中继循环 XOR 密钥素材
	NodeList    []NodeAddr `json:"node_list"`     // UDP 关联用入口
	TCPNodeList []NodeAddr `json:"tcp_node_list"` // TCP CONNECT 用入口
}

// APIClient 访问小黑盒加速账号 API（控制面）。
type APIClient struct {
	HeyboxID  int64
	Pkey      string
	ISP       string // all/dianxin/liantong/yidong/bgp，空为 all
	Base      string
	machineID string
	hc        *http.Client
}

// NewAPIClient 创建控制面客户端。machineID 模拟原版机器标识（服务端松散校验）。
func NewAPIClient(heyboxID int64, pkey, isp, base string) *APIClient {
	if base == "" {
		base = DefaultAPIBase
	}
	if isp == "" {
		isp = "all"
	}
	return &APIClient{
		HeyboxID:  heyboxID,
		Pkey:      pkey,
		ISP:       isp,
		Base:      base,
		machineID: randomUUID(),
		hc: &http.Client{
			Timeout: apiRequestTimeout,
			Transport: &http.Transport{
				// 走 mihomo 托管解析（DefaultResolver→SystemResolver）；
				// 禁用裸系统 DNS（main.go 挂了 net.DefaultResolver 防护钩子）
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					if resolver.DefaultResolver == nil && resolver.SystemResolver == nil {
						// 无 mihomo DNS 环境（独立进程/单测）：直接系统解析
						var d net.Dialer
						return d.DialContext(ctx, network, address)
					}
					return dialer.DialContext(ctx, network, address)
				},
				TLSHandshakeTimeout: 10 * time.Second,
				IdleConnTimeout:     30 * time.Second,
			},
		},
	}
}

func randomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

// randomNonce 生成 32 位混合大小写字母数字（对应原版 main.GetRandomString(32)）。
func randomNonce() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var b [32]byte
	_, _ = rand.Read(b[:])
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b[:])
}

// commonQuery 构造公共查询参数（逆向自 CommonQueryParams @0xa77c20）。
func (c *APIClient) commonQuery(path string) string {
	now := time.Now().Unix()
	nonce := randomNonce()
	q := url.Values{}
	q.Set("hkey", GenerateHkey(path, now, nonce))
	q.Set("heybox_id", strconv.FormatInt(c.HeyboxID, 10))
	q.Set("os_type", "pc_proxy")
	q.Set("client_type", "acc_pc")
	q.Set("download_source", "xiaoheihe")
	q.Set("machine_id", c.machineID)
	q.Set("device_id", c.machineID)
	q.Set("x_app", "heybox_acc_pc")
	q.Set("x_os_type", "Windows")
	q.Set("x_client_type", "pc")
	q.Set("version", apiVersion)
	q.Set("_time", strconv.FormatInt(now, 10))
	q.Set("nonce", nonce)
	return q.Encode()
}

// form 构造表单体（heybox_id + pkey + session_id=0 + uuid）。
func (c *APIClient) form() url.Values {
	f := url.Values{}
	f.Set("heybox_id", strconv.FormatInt(c.HeyboxID, 10))
	f.Set("pkey", c.Pkey)
	f.Set("session_id", "0")
	f.Set("uuid", c.machineID)
	return f
}

// post 发送 POST 并解密 result 字段到 out。
func (c *APIClient) post(ctx context.Context, path, query string, out any) error {
	reqURL := c.Base + path + "?" + query + "&" + c.commonQuery(path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(c.form().Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", apiUserAgentPC)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Cookie", fmt.Sprintf("user_heybox_id=%d; user_pkey=%s; heybox_id=%d; pkey=%s",
		c.HeyboxID, c.Pkey, c.HeyboxID, c.Pkey))

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("heybox api %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("heybox api %s: read body: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heybox api %s: HTTP %d: %s", path, resp.StatusCode, truncate(string(body), 200))
	}
	var envelope struct {
		Status string `json:"status"`
		Msg    string `json:"msg"`
		Result string `json:"result"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("heybox api %s: bad json: %w", path, err)
	}
	if envelope.Status != "ok" {
		return fmt.Errorf("heybox api %s: status=%s msg=%s", path, envelope.Status, envelope.Msg)
	}
	plain, err := DecryptConfigResult(envelope.Result)
	if err != nil {
		return fmt.Errorf("heybox api %s: decrypt result: %w", path, err)
	}
	if err := json.Unmarshal(plain, out); err != nil {
		return fmt.Errorf("heybox api %s: unmarshal result: %w", path, err)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// UsedGameList 枚举账号的游戏/设备条目（无会话副作用）。
func (c *APIClient) UsedGameList(ctx context.Context) ([]GameEntry, error) {
	q := url.Values{}
	q.Set("offset", "0")
	q.Set("limit", "1000")
	q.Set("game_type", "0")
	q.Set("cur_acc_id", "0")
	var out struct {
		GameList []GameEntry `json:"game_list"`
	}
	if err := c.post(ctx, "/proxy/used_game_list_for_pc/", q.Encode(), &out); err != nil {
		return nil, err
	}
	return out.GameList, nil
}

// AbroadNodeList 枚举指定游戏、指定大区下的节点列表（无会话副作用，session_id=0）。
func (c *APIClient) AbroadNodeList(ctx context.Context, accID, districtID int) ([]AbroadNode, error) {
	q := url.Values{}
	q.Set("acc_district_id", strconv.Itoa(districtID))
	q.Set("acc_id", strconv.Itoa(accID))
	q.Set("offset", "0")
	q.Set("limit", "100")
	if c.ISP != "all" {
		q.Set("isp", c.ISP)
	}
	q.Set("isp_filter", "0")
	var out struct {
		NodeList []AbroadNode `json:"node_list"`
	}
	if err := c.post(ctx, "/proxy/get_abroad_node_list/", q.Encode(), &out); err != nil {
		return nil, err
	}
	return out.NodeList, nil
}

// NodeConfigParams 是分配会话（proxy_node_list）的请求参数。
type NodeConfigParams struct {
	AccID          int
	GameID         int
	ServerRegion   int    // 大区 ID
	NodeName       string // 节点名（枚举结果），空为自动选择
	AccMode        int    // 加速模式，0 时用 1
	TransportProto string // 默认 udp
	ISP            string
}

// NodeConfig 分配一个会话：响应原子携带 session_id、握手密钥、协议版本与节点端口。
// 多次分配互不顶替（实测 §12），会话长时间存活且不绑客户端 IP。
func (c *APIClient) NodeConfig(ctx context.Context, p NodeConfigParams) (*NodeConfig, error) {
	accMode := p.AccMode
	if accMode == 0 {
		accMode = 1
	}
	tp := p.TransportProto
	if tp == "" {
		tp = "udp"
	}
	isp := p.ISP
	if isp == "" {
		isp = c.ISP
	}
	q := url.Values{}
	q.Set("acc_id", strconv.Itoa(p.AccID))
	q.Set("game_id", strconv.Itoa(p.GameID))
	q.Set("server_region", strconv.Itoa(p.ServerRegion))
	q.Set("node_name", p.NodeName)
	q.Set("acc_mode", strconv.Itoa(accMode))
	q.Set("transport_proto", tp)
	if isp != "" && isp != "all" {
		q.Set("isp", isp)
	}
	q.Set("is_wireless", "false")
	q.Set("yy", "false")
	q.Set("save", "false")
	q.Set("isp_filter", "")
	q.Set("common_app", "false")
	q.Set("lock_region", "0")
	var cfg NodeConfig
	if err := c.post(ctx, "/proxy/proxy_node_list/", q.Encode(), &cfg); err != nil {
		return nil, err
	}
	if len(cfg.NodeList) == 0 {
		return nil, fmt.Errorf("heybox api: node_list empty for node %q region %d", p.NodeName, p.ServerRegion)
	}
	return &cfg, nil
}

// XORKey 返回 TCP 数据通道的循环 XOR 密钥（xor_bytes 的 base64 解码；空/无效返回 nil）。
func (n *NodeConfig) XORKey() []byte {
	if n.XorBytes == "" {
		return nil
	}
	if k, err := base64.StdEncoding.DecodeString(n.XorBytes); err == nil && len(k) > 0 {
		return k
	}
	return nil
}

// EntryNode 返回 UDP 关联入口地址。
func (n *NodeConfig) EntryNode() string {
	if len(n.NodeList) == 0 {
		return ""
	}
	return n.NodeList[0].IP + ":" + strconv.Itoa(n.NodeList[0].Port)
}

// TCPNode 返回 TCP CONNECT 入口地址（独立端口，如 5085）。
func (n *NodeConfig) TCPNode() string {
	if len(n.TCPNodeList) == 0 {
		return ""
	}
	return n.TCPNodeList[0].IP + ":" + strconv.Itoa(n.TCPNodeList[0].Port)
}
