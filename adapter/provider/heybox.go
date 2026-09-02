package provider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/heybox"
)

// heyboxProviderSchema 是 type: heybox 的 provider 配置。
type heyboxProviderSchema struct {
	HeyboxID int64  `provider:"heybox-id"`
	Pkey     string `provider:"pkey"`
	Games    []int  `provider:"games"` // acc_id 列表（必填，无默认全部）
	ISP      string `provider:"isp,omitempty"`
	APIBase  string `provider:"api,omitempty"`
}

// HeyboxVehicle 枚举账号下指定游戏的加速节点（无会话副作用），
// 渲染为标准 proxies YAML。渲染结果不含账号凭证——凭证在 parser 层注入，
// 因此磁盘缓存（vehicle.Write 落盘）天然脱敏。
type HeyboxVehicle struct {
	api   *heybox.APIClient
	games []int
	path  string
}

func NewHeyboxVehicle(name string, schema *heyboxProviderSchema) *HeyboxVehicle {
	return &HeyboxVehicle{
		api:   heybox.NewAPIClient(schema.HeyboxID, schema.Pkey, schema.ISP, schema.APIBase),
		games: schema.Games,
		path:  C.Path.GetPathByHash("proxies", "heybox://"+name),
	}
}

func (v *HeyboxVehicle) Type() P.VehicleType { return P.Heybox }
func (v *HeyboxVehicle) Path() string        { return v.path }
func (v *HeyboxVehicle) Url() string         { return "heybox://" + v.path }
func (v *HeyboxVehicle) Proxy() string       { return "" }

func (v *HeyboxVehicle) Write(buf []byte) error {
	dir := strings.LastIndexByte(v.path, os.PathSeparator)
	if dir > 0 {
		_ = os.MkdirAll(v.path[:dir], 0o755)
	}
	return os.WriteFile(v.path, buf, 0o644)
}

// Read 枚举并渲染 proxies YAML；API 失败时回退磁盘缓存（防止重启变砖）。
func (v *HeyboxVehicle) Read(ctx context.Context, oldHash utils.HashType) (buf []byte, hash utils.HashType, err error) {
	buf, err = v.render(ctx)
	if err != nil {
		// 回退：上次成功枚举的脱敏缓存
		if cached, cErr := os.ReadFile(v.path); cErr == nil && len(cached) > 0 {
			log.Warnln("[Provider] heybox enumerate failed (%v), fallback to cache %s", err, v.path)
			return cached, utils.MakeHash(cached), nil
		}
		return nil, oldHash, err
	}
	return buf, utils.MakeHash(buf), nil
}

// render 走无副作用枚举链路：used_game_list_for_pc → 每游戏每大区 get_abroad_node_list，
// 每个 (游戏 × 大区 × 节点) 渲染一条 type: heybox 的 proxy 定义（不含凭证）。
func (v *HeyboxVehicle) render(ctx context.Context) ([]byte, error) {
	games, err := v.api.UsedGameList(ctx)
	if err != nil {
		return nil, err
	}
	wanted := make(map[int]struct{}, len(v.games))
	for _, g := range v.games {
		wanted[g] = struct{}{}
	}

	var proxies []map[string]any
	var matched int
	for _, g := range games {
		if _, ok := wanted[g.AccID]; !ok {
			continue
		}
		matched++
		gameName := sanitizeProxyName(g.Name)
		accMode := g.CurrentModeID
		if accMode == 0 {
			accMode = 1
		}
		for _, district := range g.AccDistrict {
			nodes, err := v.api.AbroadNodeList(ctx, g.AccID, district.ID)
			if err != nil {
				log.Warnln("[Provider] heybox %s district %s enumerate failed: %v", gameName, district.Name, err)
				continue
			}
			for _, node := range nodes {
				proxies = append(proxies, map[string]any{
					"name":            gameName + "-" + node.Name,
					"type":            "heybox",
					"acc-id":          g.AccID,
					"game-id":         g.GameID,
					"server-region":   district.ID,
					"node-name":       node.Name,
					"acc-mode":        accMode,
					"transport-proto": "udp",
					"node-ip":         hostOnly(node.Src),
					"udp":             true,
				})
			}
		}
	}
	if matched == 0 {
		return nil, fmt.Errorf("heybox: none of games %v found in account game list", v.games)
	}
	if len(proxies) == 0 {
		return nil, errors.New("heybox: no node available for configured games")
	}

	schema := &ProxySchema{Proxies: proxies}
	return yaml.Marshal(schema)
}

// wrapHeyboxCredParser 在标准 proxies 解析前注入账号凭证（仅内存，不落盘）。
func wrapHeyboxCredParser(parser resource.Parser[[]C.Proxy], schema *heyboxProviderSchema) resource.Parser[[]C.Proxy] {
	return func(buf []byte) ([]C.Proxy, error) {
		s := &ProxySchema{}
		if err := yaml.Unmarshal(buf, s); err != nil {
			return parser(buf) // 非 YAML（不应发生）：原样交给标准解析器报错
		}
		for _, m := range s.Proxies {
			if t, _ := m["type"].(string); t != "heybox" {
				continue
			}
			if _, ok := m["heybox-id"]; !ok {
				m["heybox-id"] = schema.HeyboxID
			}
			if _, ok := m["pkey"]; !ok {
				m["pkey"] = schema.Pkey
			}
			if _, ok := m["isp"]; !ok && schema.ISP != "" {
				m["isp"] = schema.ISP
			}
			if _, ok := m["api"]; !ok && schema.APIBase != "" {
				m["api"] = schema.APIBase
			}
		}
		injected, err := yaml.Marshal(s)
		if err != nil {
			return nil, err
		}
		return parser(injected)
	}
}

func sanitizeProxyName(s string) string {
	s = strings.TrimSpace(s)
	replacer := strings.NewReplacer("/", "-", "\\", "-", " ", "-")
	return replacer.Replace(s)
}

func hostOnly(hostPort string) string {
	if host, _, err := net.SplitHostPort(hostPort); err == nil {
		return host
	}
	return hostPort
}
