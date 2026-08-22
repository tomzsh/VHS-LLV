# 子域名接管 (Subdomain Takeover)

> 视角：黑盒，目标是找到指向"已释放第三方资源"的悬空 DNS 记录

## 1. 一句话说清

接管 = 子域名的 CNAME 指向第三方服务（Heroku/Shopify/S3/...），但对方资源已被删除且
DNS 记录未清理。攻击者重新注册该资源即控制子域内容。
SRC 价值：许多程序按 Critical/High 支付（先查程序政策是否纳入 takeover——
`non-qualifying.md` 只是默认模板，程序政策优先）。

---

## 2. 高频入口点

| 来源 | 说明 |
|------|------|
| 子域枚举输出 | subfinder/assetfinder/amass 结果 → 逐个查 CNAME |
| 历史 DNS | SecurityTrails / ViewDNS 历史 CNAME 快照 |
| JS 引用 | 页面与 JS bundle 中引用的内部子域（最易漏） |
| 证书透明日志 | crt.sh 里存在但已停止解析的子域 |
| 云迁移残留 | 迁到新平台后旧 CNAME（herokuapp / cloudfront / azurewebsites）未删 |

---

## 3. 探测手法

### 3.1 批量 CNAME 枚举

```
dnsx -l hosts_scoped.txt -cname -json -silent
# VHS 自带（含悬空判定 + 指纹库 + hypothesis 导出）：
python3 scripts/takeover_check.py ./engagement --run-dir ./run-output --append-hypotheses
```

### 3.2 悬空判定（NXDOMAIN + 指纹双条件）

```
dig CNAME stale.target.com      # → xxx.herokuapp.com.
dig xxx.herokuapp.com +short    # → 空 = 已释放
curl -s https://stale.target.com | head   # 服务商"不存在"页面
```

### 3.3 HTTP 响应指纹（辅助确认）

```
Heroku    → "No such app" + 404
Shopify   → "Sorry, this shop is currently unavailable"
S3        → "NoSuchBucket" + 404
Zendesk   → "Help Center Closed" / "this help center no longer exists"
Pantheon  → "404 error unknown site"
Azure     → "404 Web Site not found"
Github    → "There isn't a GitHub Pages site here."（已缓解，仅信息级）
```

### 3.4 工具

```
- scripts/takeover_check.py（内置 references/takeover-fingerprints.json 指纹库）
- nuclei -t takeovers/ （官方 takeover 模板集）
- subjack / subzy（指纹对照工具）
- 参考数据集：EdOverflow/can-i-take-over-xyz（status: claimable/partial/discontinued）
```

---

## 4. Bypass 矩阵（误报排除与变体）

| 障碍 / 变体 | 处理 |
|---|---|
| CNAME 链（A→B→C） | 逐跳解析，悬空可能在链尾而非第一跳 |
| 通配符 DNS 造成"全部悬空"假象 | 用不存在的随机标签对照（random123.target.com 同样 NXDOMAIN = 通配符，误报） |
| CloudFront（partial） | 需存在 alternate domain 匹配的 distribution 才可 claim，默认不可 |
| 已缓解服务（GitHub Pages/Fastly/Bitbucket） | 标记 discontinued，只作信息级报告 |
| 解析超时误判 NXDOMAIN | 复测 2 次 + 换 resolver（1.1.1.1 / 8.8.8.8） |
| CNAME 大小写/尾点 | 归一化后匹配指纹库 |

---

## 5. 价值升级路径（不自动 claim）

> Claim 资源 = controlled-impact 动作，必须先获程序明确批准，VHS 工具永不自动执行。

```
可控制受信任域内容 → 钓鱼/内容注入可信度大幅提升
同父域下可种 cookie（cookie tossing）→ 会话固定 / CSRF 辅助
OAuth redirect_uri / JWKS allowlist 含该子域 → 打通账号接管链（配合 oauth-saml-jwt.md）
CSP 白名单含该子域 → XSS payload 加载源
```

---

## 6. 真实案例指纹

| 服务 | 指纹域 | 状态 |
|---|---|---|
| Heroku | herokudns.com / herokuapp.com | claimable |
| Shopify | myshopify.com | claimable |
| AWS S3 | s3.amazonaws.com / s3-website-* | claimable |
| Zendesk | zendesk.com | claimable |
| Azure | azurewebsites.net / cloudapp.net | claimable |
| CloudFront | cloudfront.net | partial |
| GitHub Pages | github.io | discontinued（仅信息级） |

完整表：`references/takeover-fingerprints.json`（26 服务，含 claimable/partial/discontinued 标注）

公开披露案例类型：Starbucks / Shopify / Uber 等大型程序的 takeover 报告（$1k–$5k 级），
多数走"marketing 残留子域 + SaaS 服务释放"路径。

---

## 7. 复现 / 证据要点

### 7.1 报告必备

1. `dig CNAME <sub>` 输出（含尾点）+ 时间戳
2. CNAME 目标的 NXDOMAIN 证明（两个 resolver 复测）
3. 指纹库/HTTP body 匹配截图
4. 程序政策纳入 takeover 的证据（政策原文引用）
5. （经批准后）claim 前/后对照 + 立即释放的说明

### 7.2 CVSS 参考

```
可 claim + 影响父域 cookie/OAuth 域    = 7.4–8.8 (High)
可 claim + 仅内容控制                 = 5.9–7.5 (Medium/High)
discontinued 指纹                     = 信息级
```

---

## 8. 不要做的事

- **禁**：未经程序批准就 claim/注册资源——这是 controlled-impact，先拿书面许可。
- **禁**：claim 后托管任何真实内容（留最小标记证明所有权即可，验证后立即释放）。
- **禁**：对程序政策明确排除 takeover 的目标提交（先查 `scope_source` 政策）。
- **限**：只解析授权范围内的子域；不爆破第三方 DNS。
- **限**：NXDOMAIN 判定必须双 resolver 复测，通配符域必须排除后才可写入 findings。
