# 专项检查 C：凭据作用域、缓存与秘密暴露

## 1. 凭据 ID 枚举也是独立安全边界

`doFillCredentialsIdItems`、自动补全和辅助 helper 若只凭 Overall/Read 返回全局或 Folder 凭据 ID，可能为后续“指定 ID + 攻击者 URL”利用提供条件。枚举 ID 不等同于读取秘密明文，但 Jenkins 历史公告反复将其认定为权限问题。

审计顺序：入口权限 → 实际 Item/Folder 上下文 → lookup 使用的 Authentication → DomainRequirement/类型过滤 → 返回字段。不要只检查最外层 `doFill`，还要检查被多个端点调用的 package/public helper。

## 2. lookup 必须带正确上下文

搜索：

```regex
CredentialsProvider\.(?:lookupCredentials|findCredentialById|lookupStores)
CredentialsMatchers|withId|findCredentials|getCredentials
```

对每次解析记录 `credentialsId + Item/Folder/Run + Authentication + Domain`。常见缺口：

- 只按攻击者给出的 ID 查全局凭据，没有真实 Item 上下文。
- Folder 配置错误声明为 System scope，使用户能选系统凭据。
- 在攻击者能控制 credential ID、目标 Item 或配置提交的路径上，错误地以 SYSTEM 取代本应使用的用户/构建认证，导致跨 Item/Folder/System scope 解析。已获授权的 Job 在内部以 SYSTEM 解析其合法范围内的凭据可以是正常设计，不能仅凭 SYSTEM 判洞。
- 类型过滤正确但作用域错误；有 `Item.CONFIGURE` 不代表可使用任意 ID。

CVE-2019-16541 是 Folder 定义错误使用 System scope 凭据；CVE-2023-49653 是凭据查找上下文不当。修复应指定真实上下文和认证，不是仅把返回密码加密。

## 3. 缓存键必须包含安全域

客户端、连接或解析后的凭据若被缓存，键只含 credential ID 会混淆不同 Folder 下同 ID 的解析结果。审计：

```text
cache key = credential ID? + Folder/Item? + Authentication? + endpoint/config?
```

CVE-2026-92133 的核心是 GitLab API client 缓存键仅由 credentials ID 派生，遗漏 Folder。对连接池、memoize、static map、TTL cache 做同样检查。验证时使用两个 Folder、相同合成 ID、不同权限/秘密，确保不能跨域复用。

## 4. “能选择”与“能使用”都要验证

下拉列表只显示允许凭据，不代表服务端提交时不能传其他 ID。沿 `@DataBoundConstructor/@DataBoundSetter`、JSON binding 和实际执行路径检查：提交后是否重新解析并限制作用域，使用前是否验证目标对象权限。

相反，仅隐藏下拉项不是修复。测试应手工提交未列出但存在的合成 credential ID，观察是否仍被用于网络、SCM 或文件操作。

## 5. EXTENDED_READ 与密文脱敏

`Item.EXTENDED_READ` 允许查看配置，不意味着应得到秘密、明文或本可脱敏的密文。追踪 config.xml、历史配置、REST/CLI、诊断页和异常响应中的：

- `Secret.getEncryptedValue()`、`SecretBytes`、Base64/明文密码。
- XML 序列化、`XmlFile`、历史快照与 diff。
- 自定义导出是否绕过标准 Jenkins redaction。

CVE-2024-47805 是 SecretBytes 在 item config.xml REST/CLI 中未脱敏；CVE-2026-57287 是历史 job/agent 配置向 Extended Read 用户显示密文。不要把“密文不能直接解密”作为无漏洞理由，也不要把所有配置读取都误报为秘密泄露。

## 6. 存储与日志遮罩

密码参数、token、OAuth access token、secret file 可能进入 build.xml、config.xml、日志或异常。检查：

- 存储是否使用 Jenkins Secret/凭据设施，历史数据是否仍暴露。
- 日志是否只遮罩 `$variable` 展开值，却漏掉异常 message、URL userinfo、编码/拼接变体。
- 遮罩是否覆盖凭据派生形式，异常 sink 是否绕开 masker。

代表：CVE-2022-27195（密码参数明文进入 build.xml）、CVE-2024-39459（secret file 仅 Base64，Folder 场景 Extended Read 可见）、CVE-2024-39460（OAuth token 随 URL 写入日志）、CVE-2025-53650（异常消息中的凭据未正确遮罩）。

这些属于凭据保护而非天然 missing permission。只有 Extended Read、跨 Folder、错误身份等访问边界存在时，才与鉴权 finding 合并；否则按秘密暴露类型单独描述。

## 7. 影响与证据边界

区分四级影响：ID/元数据枚举、文件或类型存在性 oracle、密文/敏感配置泄露、明文或可用凭据泄露。不要把 ID 枚举夸大为直接账号接管；若需第二个漏洞才能捕获秘密，应在 exploit_chain 和 preconditions 明确依赖。

PoC 只用合成凭据。证明“请求带认证到达本地伪服务”即可，不展示真实 token，不访问外部服务。
