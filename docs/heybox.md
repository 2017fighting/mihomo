# 小黑盒加速器（heybox）集成

将小黑盒加速器的加速节点接入 mihomo，用于路由器透明代理场景下的主机游戏加速
（Switch 等）。协议逆向与设计决策见 `docs/adr/0002` 与词汇表 `CONTEXT.md`。

## 当前状态（全链路在线验证通过）

| 链路 | 状态 | 说明 |
| --- | --- | --- |
| 控制面（枚举/会话分配/hkey 签名） | ✅ | `proxy_node_list` 等三接口全通 |
| UDP 数据面（明文中继） | ✅ | DNS 经中继往返实测 |
| TCP CONNECT 数据面（XOR 层） | ✅ | conntest 经节点返回 `HTTP/1.1 200 OK`（Nintendo 组织头） |

TCP 数据通道为**双向循环 XOR**（密钥 = 会话 `xor_bytes` base64 解码，读写独立计数，
握手帧不参与——类似 startTLS 的分层升级）；UDP 中继为明文，不走此层。
详见 heybox_acc 仓库 PROTOCOL.md §5/§13。

## 原理

- **provider（`type: heybox`）= 纯枚举**：刷新时走无副作用链路
  （`used_game_list_for_pc` → 每游戏每大区 `get_abroad_node_list`），
  把每个 (游戏, 大区, 节点) 渲染成一条 `type: heybox` proxy，**不产生会话**。
- **proxy = 惰性会话持有者**：首次被选中时调 `proxy_node_list` 取会话
  （session_id / 握手密钥 / 协议版本 / 节点端口同响应原子下发）并缓存，
  UDP ASSOCIATE 与 TCP CONNECT 共享；REP 类错误自动作废重拉一次
  （网络类错误保留会话，避免无谓重拉触发风控）。
- 新旧会话并发共存、长时间存活且不绑客户端 IP（逆向实测结论）。

## 配置示例

```yaml
proxy-providers:
  heybox:
    type: heybox
    heybox-id: 16651571          # 小黑盒账号 ID
    pkey: "MTc4..."              # 登录凭据，每次登录轮换，需自行抓取
    games: [356]                 # acc_id 列表，必填（356 = Switch）
    # isp: liantong              # 可选：all(默认)/dianxin/liantong/yidong/bgp
    # api: https://accapi.xiaoheihe.cn   # 可选：API 地址覆盖
    # interval: 600              # 默认 600s：枚举刷新 = 更新节点列表与延迟数据（无会话副作用）
    # 探活/测速 = 节点入口 UDP echo（零会话零 TCP），无需配置 health-check

proxy-groups:
  - name: Switch加速
    type: url-test
    url: http://www.baidu.com/   # 占位（heybox 测速经 UDP echo，不实际请求）
    interval: 600
    use:
      - heybox
    filter: "Switch.*日本"       # 按大区筛选（节点名自带大区前缀，如 Switch-通用-日本3）

rules:
  # 游戏服务器 IP 段 UDP（联机主场景）
  - IP-CIDR,185.34.0.0/16,Switch加速,udp
  # 任天堂域名 TCP（eShop/系统更新等）
  - DOMAIN-SUFFIX,nintendowifi.net,Switch加速
  - DOMAIN-SUFFIX,nintendo.net,Switch加速
  - MATCH,DIRECT
```

生成的 proxy 名为 `{游戏名}-{节点名}`（如 `Switch-通用-日本3`、`Switch-通用-香港130`），
可用 provider 的 `filter`/`exclude-filter` 与分组正则自由组合。

## 探活与测速模型（与标准 provider 不同）

- **健康检查/组测速/面板测速 = 节点入口 UDP echo 实测 RTT**（枚举响应自带回声地址；
  原版客户端同款机制），零会话、零 TCP，不会再触发服务端风控
- 枚举响应的 `rtt_avg`（<999 有效）作首轮初始值与 echo 失败时兜底
- heybox provider **不配置 health-check**（写了也会被忽略）；`interval` 默认 600s，
  含义为枚举刷新（节点列表 + 延迟数据），刷新动作无会话副作用
- 会话仅在真实流量选中节点时按 `node_name` 分配（选中 ≠ 分配）

## 手动刷新

provider 默认不自动定时刷新（刷新语义 = 重新枚举节点列表）。通过 RESTful API 触发：

```sh
curl -X PUT http://127.0.0.1:9090/providers/proxies/heybox \
  -H "Authorization: Bearer <secret>"
```

## UDP 可用性测试

```sh
# PC 快速验证（经 mihomo 混合端口 SOCKS5-UDP → 节点中继 → DNS 往返）
python3 test-heybox-acc/udp_test.py [mihomo地址:端口] [DNS服务器] [查询域名]
```

注意：Switch 自带的"互联网连接测试"走 conntest（TCP/HTTP），
经加速节点返回的应答格式非标准 HTTP，可能测试失败——**不代表联机不可用**，
请直接进游戏测在线对战。

## 运维须知（风险与边界）

1. **pkey 过期**：每次在 PC/手机登录小黑盒账号 pkey 都会轮换。过期后 provider
   刷新失败：保留旧节点列表并打错误日志；需重新抓取 pkey 更新配置。
2. **账号互踢**：同一账号在官方客户端上开启加速会触发控制面互踢
   （`acc_status.is_acc_in_other_client`），路由器侧会话失效——自愈逻辑会在下次
   连接时自动重拉恢复；避免双端同时加速。
3. **会话风控**：探活已改为 UDP echo（零会话），剩余风险仅来自频繁重启后首个
   真实流量触发的分配。若仍遇拨号超时（节点侧临时拉黑），静置几分钟即恢复。
4. **节点只接受 IP 目标且 TCP 端口受限**：出站已内置域名预解析（与原版行为一致）；
   TCP CONNECT 仅 80/443 等端口放行（其余 REP=0x0a）。
5. **磁盘缓存脱敏**：provider 枚举结果落盘缓存不含 pkey（凭证仅在内存注入），
   API 不可用时可回退缓存，避免路由器重启变砖。
