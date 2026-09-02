# heybox 健康检查与会话彻底解耦：UDP echo 探活 + 流量触发会话

ADR-0002 确立了"provider=纯枚举、proxy=惰性会话"，但健康检查仍走 mihomo 标准
URLTest（TCP 拨测），首轮会触发每 proxy 一次会话分配（N 节点 = N 次
`proxy_node_list`），实测诱发服务端风控（拨号超时、静置恢复）。本决策将探活
与 TCP/会话彻底解耦：

- **探活 = 节点入口的 UDP echo ping**（`get_abroad_node_list` 响应自带
  `src` = 入口 IP:udp_echo_port，8 字节时间戳回显，原版客户端同款机制），
  零会话、零 TCP。枚举响应的 `rtt_avg`（<999）作初始值与兜底。
- **会话仅在真实流量时分配**：健康检查/组测速/面板测速都不再触发
  `proxy_node_list`；选中节点 ≠ 分配会话。
- 为此在核心 `adapter.Proxy.URLTest` 增加可选接口委托（`DelayHinter`），
  实现 `DelayHint` 的出站用自定义测速替代真实 HTTP 拨测；其余出站零影响。
- provider 默认 `interval: 600`（枚举无副作用，刷新 = 更新节点列表与延迟数据）；
  heybox provider 不再支持 `health-check` 配置（忽略并禁用）。

## Considered Options

- **每游戏共享单会话 + 节点端口缓存**（依 §11.7 会话跨节点通用）：可把分配量
  从 N 降到 1，但需引入端口学习/持久化层；在本方案（探活零会话）下分配仅发生在
  真实流量选中时，量级已足够小，复杂度不值——已分析未采用。
- **不改核心，select-only + rtt_avg 展示**：失去自动选优与探活，放弃。

## Consequences

- 面板/组的"延迟"语义变为 echo RTT（与游戏包路径同源，比 HTTP 拨测更贴近真实）。
- 探活流量：每节点每次测速 1 个 UDP 包，interval 600s × N 节点，可忽略。
- supersedes ADR-0002 中"冷启动首轮健康检查会失败"的后果描述。
