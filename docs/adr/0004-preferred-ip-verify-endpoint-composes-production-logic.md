# preferred-ip 验证端点：组合生产改写逻辑，而非走真实 DNS 链路

日期: 2026-09-03 · 状态: accepted

## 决定

新增只读端点 `GET /preferred-ip/verify?name=<域名>`：对域名做一次实时解析，然后**复用两条改写钩子共享的同一套 `Match` + `AnswerPool` 纯函数逻辑**判定结果，一次调用同时返回 v4/v6 两族的判定。配套的状态面增强：`EntryStatus` 增加 `testing`（测速进行中标志）与 `ranges`（只读段集合展示）；`POST /preferred-ip/speedtest` 把「已在队列」从 404 中拆出，改返 `409 Conflict`。

verdict 枚举（契约随本 ADR 钉死）：

- `rewritten` — 改写生效：A 答案被优选池前 N 条替换，或 AAAA 自 v6 池应答
- `blocked` — 已拦截：`ipv6: block` 命中段集合，AAAA 空答案（生效形态，非故障）
- `passthrough-no-match` — 正确透传：解析结果不落在任何段集合（提示可能测错域名）
- `passthrough-pool-empty` — 池未就绪：命中但对应族优选池为空（区分 v4/v6，可操作信号）
- `resolve-error` — 解析失败：上游解析本身出错

## 否决的替代

- **复用现有 `GET /dns/query`**：它调 `DefaultResolver.ExchangeContext`，两条改写路径（DNS server 中间件 / `lookupIP` 内部出口）都不经过，返回上游原始答案——功能完全正常时它也显示「未改写」，是主动误导。
- **走真实 DNS 链路（DoH 监听）**：依赖用户启用 DoH 且浏览器 CORS 放行，不通用；UDP 53 浏览器不可达。
- **前端拿 `/dns/query` + ranges 自行模拟 Match**：只能证明「会触发」，证明不了实际输出；且改写语义复制到前端必然漂移。

## 后果

- verify 走「实时解析 + 共享改写器」组合路径，**不含** DNS server 链路中位于改写外侧的 `withHosts`：若 hosts 表覆盖了被测域名，生产链路会先被 hosts 短路，verdict 仍会报 `rewritten`——该角落的差异已知并接受（hosts 是显式用户配置，优先于改写是既有语义）。
- verdict 枚举与响应形状是对外契约，发版后难改；增枚举值只许追加。
- `testing` 标志供 UI 轮询收敛（测速进行中 2-3s 轮询，静止不轮询）。
