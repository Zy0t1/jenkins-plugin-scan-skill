# 专项检查 B：CSRF、构建身份与再审批

## 1. CSRF 必须与权限分开判断

状态修改、角色/配置变更、任务触发、外部连接测试、带凭据的 URL 请求，即使 Java 方法名是 `doCheck` 或“测试”，也可能有副作用。审计四元组：

```text
HTTP verb | Jenkins crumb | 权限检查 | 实际副作用
```

`@POST`/`@RequirePOST` 解决请求方式/CSRF 面的一部分，不提供业务授权；`checkPermission` 也不自动把危险 GET 变成安全端点。两者通常都需要。不同 Jenkins core 对注解与 crumb 处理有版本差异，必须跟踪实际 interceptor，不要只凭注解名声称已防 CSRF。

高风险信号：

- `do*` 修改配置/角色/任务或发起构建，却没有 POST 约束。
- form validation 接收 URL 和 credential ID，向攻击者服务器发请求。
- 新加 `@POST` 但漏掉 Item/ADMINISTER 检查，或反过来。
- `CrumbExclusion`/webhook 正规化路径绕过，且没有替代签名认证。

代表 CVE：Role-based Strategy 改角色的 CVE-2017-1000090；Subversion 表单校验的权限+CSRF 复合问题 CVE-2017-1000085。其他 CVE 可作为同类检索起点，但不能据 CVE 数量推断当前代码有洞。

## 2. “只读外观”的副作用

下列名字不能作为只读证明：`doCheck`、`doTestConnection`、`doValidate`、`doFill`、`doDiscover`。沿调用树检查：

- 是否打开网络连接并发送凭据、认证头或挑战响应。
- 是否创建目录、写缓存、改配置、启动任务或修改角色。
- 是否返回控制器文件存在性、内部拓扑或敏感列表。

对外连接即使最终无数据修改，也可能被 CSRF 用于凭据捕获或 SSRF，因此仍需权限和请求来源防护。

## 3. 构建身份传播

对 trigger/parameterized build/pipeline node/replay 等路径，记录三个身份：浏览器调用者、源构建身份、目标执行身份。常见问题：

- 只验证源 Job，不验证调用者对目标 Job 的 Item/Build。
- 调度时丢掉原认证，异步队列以 SYSTEM 执行。
- 授权插件给出的构建身份缺 Computer/Build，却仍能进入 agent 的 `node` 块。
- 以“内部可信调用”为由跳过外部请求路径的权限。

代表 CVE-2017-1000084（Parameterized Trigger 未检查构建身份与目标构建权限）和 CVE-2018-1000015（node 块未强制构建身份在 agent 上的 Computer/Build）。`ACL.SYSTEM` 只作线索，需证明跨边界影响。

## 4. Rebuild/Replay/Restart 的审批时效

脚本“曾经批准”不等于“现在仍批准”。对 Jenkinsfile、Pipeline libraries、Groovy 脚本和模板，比较：

```text
旧 build 保存的脚本/ID → 当前 ScriptApproval 状态 → 新执行动作
```

检查是否重新计算/校验当前脚本哈希、classpath 和审批，而非复用旧 build 的批准标记。还要注意 TOCTOU：审批对象与实际加载对象必须一致。

代表 CVE-2024-52550：rebuild 未重新检查主 Jenkinsfile 是否仍获批准；CVE-2024-52551：从 stage restart 的同类缺口。最低权限 Item/Build 不意味着能执行已撤销审批的脚本。

## 5. 身份模拟与作用域

搜索 `ACL.impersonate`、`ACL.as(2)`、`ACL.SYSTEM(2)`、`Tasks.getAuthenticationOf`、`Jenkins.getAuthentication(2)`。验证：

- 用户可控动作发生在哪个 Authentication 下。
- SYSTEM 是否只包住必要的内部调用，且 finally/try-with-resources 恢复。
- 异步任务、listener、queue executable 是否保留正确授权主体。
- 权限检查是否错误地使用当前线程 SYSTEM 而非原始用户/构建身份。

## 6. 负向测试设计

- GET 不得造成状态变化；POST 无 crumb 在依赖 Jenkins crumb 防护的普通 Web 端点上不得造成状态变化。采用独立签名认证的 webhook 应按其认证协议测试，不能机械要求 Jenkins crumb。
- 有效 crumb 但低权限仍必须被授权逻辑拒绝，且不得泄露数据或到达 sink。实际响应可能是 403、为避免对象枚举而返回的 404、空下拉或 FormValidation 错误，不把固定状态码当唯一安全条件。
- 授权用户对允许对象成功，对另一 Job/Folder 拒绝；同时检查响应是否泄露未授权对象信息。
- 撤销脚本批准后 rebuild/replay/restart 拒绝；重新批准或审批新脚本后才允许。
- 匿名 webhook 无签名拒绝，有效签名仅操作绑定对象。

修复建议应精确到缺口：权限、POST/crumb、身份传递、当前审批分别说明，不用笼统“加强鉴权”。
