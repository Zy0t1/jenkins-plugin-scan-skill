# 专项检查 D：鉴权后的执行与数据边界

本文件只在入口涉及文件、XML、模板、Groovy、表达式或 classpath 时加载。XXE、路径遍历和 sandbox bypass 不自动等于鉴权漏洞；应明确低权限主体跨越了哪个 Jenkins 权限、Folder、身份或脚本审批边界。

## 1. 控制器文件路径

关注 `doCheck*`、input 参数、SCM 脚本路径、timestamp/input ID、归档与上传。路径防护必须覆盖绝对路径、`..`、分隔符变体、规范化后越界和符号链接。

审计链：

```text
Web/Pipeline 参数 → 基目录拼接 → normalize/canonical/real path → symlink 处理 →
controller File/FilePath 读、写、删或存在性响应
```

仅 `new File(base, input).getCanonicalPath().startsWith(base)` 可能因路径前缀兄弟目录而出错；基目录应带分隔边界，并考虑符号链接与平台大小写。不要只看字符串过滤。

代表：CVE-2022-25176（读取 Jenkinsfile 时跟随 symlink 越出 checkout）、CVE-2022-34177（input file 参数名用于控制器归档路径）、CVE-2023-41930/CVE-2023-41932（路径参数与文件/目录操作）。CVE-2025-58458 则只是文件存在性 oracle，应与任意读写区分。

## 2. XXE 的跨信任域

XML parser 出现并不足够。证明攻击者能控制被解析 XML，解析发生在更高权限的 controller，而外部实体可读取 controller 文件、发起请求或泄露数据。

检查 SAX/DOM/StAX/JAXB 等实际 parser 设置是否同时禁止 DOCTYPE、外部 general/parameter entities 和外部 DTD，并禁用 XInclude/扩展访问（按 parser 适用）。设置一个 feature 或依赖“默认安全”需实证。

CVE-2019-10327 的关键边界是 agent 临时目录内容影响 Jenkins master 的 XML 解析；不要把它简化成普通本地文件解析。

## 3. Groovy/Script Security sandbox

审计所有能让用户定义脚本、Pipeline library、email template、classpath 或表达式的入口。统一进入 `GroovySandbox`/`SandboxInterceptor` 与 `ScriptApproval`，而非临时黑名单或正则。

重点路径：

- 构造器、map/named-arg constructor、closure 默认参数、动态属性/方法、coercion、null receiver。
- Folder 内模板是否绕开全局 Script Security。
- rebuild/replay/restart 是否重新验证当前审批。
- 同一 URL/内容是否审批一次、加载另一次，形成 TOCTOU。

代表：CVE-2023-24422（map constructors）、CVE-2023-25765（Folder email template 未纳入 sandbox）、CVE-2026-92123（null receiver 操作未拦截）、CVE-2026-92128（第一次下载用于审批、第二次下载用于加载）。

不要根据某个语言特性“看起来危险”构造 RCE 结论。必须确认目标版本 interceptor 覆盖、攻击者脚本权限和可控代码路径；动态验证仅在隔离 controller 测试环境做无害标记。

## 4. 表达式、模板与反序列化

JEXL/EL/Velocity/FreeMarker/Jelly/Groovy 等模板若能访问对象图、类加载或方法调用，检查可用变量、resolver、允许列表和 sandbox。配置反序列化则检查类型白名单与绑定权限。不要把 HTML 转义当代码执行防护。

若入口要求管理员且该能力本来就是管理员预期，应降级；若低权限 Item/Configure 或 Folder 管理能进入 controller JVM 执行，则通常是高价值边界。

## 5. 报告归类

- 主因是缺权限：类型写 Missing Authorization / Incorrect Authorization，危险 sink 放 exploit_chain。
- 主因是 sandbox/审批绕过：写 Sandbox Bypass 或 Improper Script Approval，不伪装成普通 CSRF。
- 主因是路径/XXE：保留 CWE-22/CWE-611 语义，同时在 description 说明攻击者权限和 controller 边界。
- 多个独立根因不要揉成一个“大 RCE”；每个 finding 指向自己的根因行和修复。
