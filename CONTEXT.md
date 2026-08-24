# Mihomo DNS 与代理核心

Mihomo（Clash Meta 系）代理核心的领域词汇。本词汇表只收本上下文特有的概念，不收通用编程概念。

## Language

### IP 优选（已实现，见 docs/adr/0001）

**优选IP（Preferred IP）**:
由测速按延迟/带宽从 CDN anycast 段中筛选出的、用于替换 DNS 答案的 IP。
_Avoid_: 加速IP、自选IP、CDN IP

**优选池（Preferred Pool）**:
一轮测速产出的、按优劣排序的优选IP有序列表；每轮测速整体替换。
_Avoid_: IP 列表、结果集

**段集合（Range Set）**:
触发改写判定的 CIDR 集合（如 Cloudflare 公布的 v4/v6 官方段）。判定是纯 IP 语义，与域名无关。
_Avoid_: IP段、白名单

**改写（Rewrite）**:
将命中段集合的 DNS A/AAAA 答案替换为优选池前 N 条的动作。只承诺「有优选才替换」，池空则透传；type65（HTTPS/SVCB）记录一律不动，由既有 disable-qtype-65 全局开关管辖。
_Avoid_: 劫持、映射

**透传**:
未命中段集合、或优选池未就绪时，原样返回上游答案的行为。特性的缺省姿态：任何异常都退化为不存在。

### 既有概念（对照）

**Hosts**:
`dns.hosts` 提供的无条件静态「域名→IP/域名」映射，先于解析发生，与改写无关。

**FakeIP**:
以假 IP 应答、连接时反向映射回域名的模式；开启时客户端不触发真实解析。

**测速（Speed Test）**:
内嵌于 mihomo、强制直连对候选 IP 做 tcping 与下载测速、产出优选池的过程。
_Avoid_: 健康检查（后者指运行期探活，测速指整轮重筛）

**持久化池（Persisted Pool）**:
写入 cache.db 的优选池副本。重启后载入即生效；池龄超过 interval 时立即补测，否则按正常排期。
