# 小黑盒加速器集成：provider 只做枚举，proxy 惰性持有会话

把小黑盒加速器（heybox）的加速节点接入 mihomo 时，会话归属是核心架构问题：协议里
`session_id`、握手密钥与节点连接端口在**同一次** `proxy_node_list` 响应中原子下发，且端口随会话轮换——mihomo 的 proxy 模型却假设 proxy 是稳定端点。我们决定拆成两层：

- **provider（`type: heybox`）= 纯枚举**：刷新时走无副作用链路（`used_game_list_for_pc` → 每游戏每大区 `get_abroad_node_list`，均带 `session_id=0`），把每个 (游戏, 大区, 节点) 渲染成一条**没有地址**的 `type: heybox` proxy，不产生任何会话。
- **proxy = 惰性会话持有者**：首次被选中时才调 `proxy_node_list`（携带自身 `server_region`/`node_name`/`acc_id`/`game_id`）取会话并缓存，singleflight 合并并发拉取，UDP/TCP/健康检查共享；关联或握手失败时作废缓存重拉一次自愈。

依据（逆向实测，见 /root/tmp/heybox_acc/PROTOCOL.md §12）：新会话不顶替旧会话、同账号多会话并发全活、会话 ≥30 分钟不回收、不绑客户端 IP——惰性+缓存策略不会互相踩踏。UDP 目的地址取**节点入口 IP + 应答 BND.PORT**（应答 BND 常为私网地址），关联用的 TCP 连接在 UDP 会话期间保持打开以维持租约。

## Considered Options

- **provider 刷新即取会话**（刷新 = 对每游戏调 `proxy_node_list` 绑定会话）：被否——每次刷新都消耗服务端会话资源，且"刷新"语义被迫变成"重启加速"，与 mihomo provider 的 interval 模型冲突。
- **每游戏单 proxy、内部封装节点故障转移**：被否——放弃 mihomo url-test/fallback 组与健康检查生态，重复造故障转移。

## Consequences

- 无会话时 proxy 没有可用延迟数据；健康检查与 url-test 组经 TCP CONNECT（`conntest.nintendowifi.net`）到会话建立后才有意义，冷启动首轮检查会失败。
- pkey 过期（每次登录轮换）时 provider 刷新失败：保留旧 proxies + 报错日志，健康检查自然转红，不做主动通知。
- 同账号在 PC 客户端开加速会触发账号级互踢（`acc_status.is_acc_in_other_client`），路由器侧会话失效——接受该风险，靠 proxy 自愈重拉恢复，文档注明。
- 会话凭证含 pkey 的内部 YAML 仅在内存中渲染，不落盘缓存。
