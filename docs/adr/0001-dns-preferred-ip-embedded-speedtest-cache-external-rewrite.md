# DNS IP 优选：内嵌测速器 + 缓存外双出口改写

日期: 2025-12-27 · 状态: accepted

## 决定

为 mihomo 增加 DNS IP 优选特性：当 DNS 答案中的 A/AAAA 记录命中配置的 CIDR 段集合（如 Cloudflare anycast 段）时，将答案替换为内嵌测速器产出的优选池前 N 条。三个核心决定：

1. **测速器内嵌**（而非消费外部 CloudflareSpeedTest 的 result.csv）。原因：部署目标是路由器（TUN 透明网关 + BT tracker 直连汇报），外部文件依赖在路由器上难维护；GPL-3 双向兼容使移植 CFST 代码合法。测速强制走 DIRECT（复用 mihomo 自带 dialer 栈，避免 TUN 回环），默认下载测速端点用 speed.cloudflare.com 而非 CFST 默认的第三方重定向服务。
2. **改写挂在 DNS 缓存外**（两个出口：`dns/middleware.go` 的 `withMapping` 内侧 + `dns/resolver.go` 的 `lookupIP` 出口），缓存内永远保存上游原始答案。原因：缓存内单点（`exchangeWithoutCache` 出口）会导致优选IP进缓存——池刷新须连坐 ClearCache，且 TTL 封顶 60s 会造成每分钟回源。缓存外双出口使池刷新即时生效、回源量不涨。
3. **中间件钩子位置在 `withMapping` 内侧**（改写先于映射记录）。原因：redir-host/TUN 模式下 DIRECT 出站对已解析的 DstIP 不重新解析（`adapter/outbound/direct.go:53`），映射表必须记录优选IP→域名，DOMAIN 规则才能继续命中，BT tracker 汇报才能继续走 DIRECT——这是本特性的核心使用场景。

## 否决的替代

- 消费外部 CFST result.csv：路由器场景文件同步维护成本高，且无法暴露 REST 触发重测。
- FakeIP 式映射（答案给假 IP、连接时反查）：与既有 FakeIP 机制冲突，且用户明确不开 fake-ip。
- 缓存内单点改写：见决定 2。
- type65 清除开关：mihomo 已有全局 `disable-qtype-65`，不重复建设。

## 后果

- 池未就绪（首测未完成/文件缺失/测速全败）时一律透传，特性自动退化为不存在。
- 测速结果持久化进 cache.db（bbolt），重启后载入即生效；池龄超过 interval 时立即补测。
- 两条钩子路径共享同一个纯函数改写器，语义测试只需一套。
