# Triage 与 Verification：反证、身份矩阵和安全复现

## 1. Triage 的快速但完整复核

每条候选至少读取入口完整方法、直接 sink、相关父类/Descriptor 和调用方。按顺序问：

1. 该路由在目标 Jenkins/Stapler 版本是否真实可达？是否需要比描述更高的权限？
2. 目标对象是什么？预期权限是否被证据支持？
3. guard 是否存在且能阻断？是否在上游 interceptor、父类、注解或统一入口完成？
4. 攻击者是否控制 URL、ID、路径、脚本、目标 Item 等关键参数？
5. sink 是否产生安全影响，还是正常功能/仅管理员预期？
6. 是否有公开 CVE/修复完全覆盖同一版本与根因？

满足不了可达性或影响时选 false_positive/low_value；缺关键上下文选 needs_more_context。只有完整高危/严重链才 keep，并提交平台规定的 FinalizedFinding。

## 2. 常见误报与排除证据

- “没有 checkPermission”但父类已检查：引用父类具体方法。
- “hasPermission 未使用”其实代码是旧片段：读取目标 commit 的真实 snippet。
- “GET CSRF”但方法无副作用：说明实际调用树。
- “凭据泄露”实际只返回当前用户有权看到的非敏感别名：区分 ID、密文和明文。
- “SYSTEM RCE”其实 SYSTEM 仅用于内部调度，用户输入在边界前已按真实身份授权。
- “路径遍历”实际发生在 agent 临时目录且无 controller 影响：降低影响或排除。
- “EXTENDED_READ 泄露”实际标准 Jenkins redaction 已生效：定位 redaction 路径。

## 3. 动态验证优先级

优先 JenkinsRule/真实插件测试，其次最小 Java harness，最后才是静态 likely。Mock 可以替代外部 HTTP、凭据后端和文件系统，但不能删掉被测的 ACL、AuthorizationStrategy、crumb 或路由逻辑。

适合 JenkinsRule 的验证：Descriptor 表单端点、Item/Folder 权限、RootAction、CSRF、构建触发、config.xml redaction。适合最小 harness 的验证：缓存键隔离、路径规范化、parser feature、审批内容与加载内容一致性。

## 4. 身份与对象矩阵

按 finding 选择必要行，不必无差别跑全部：

| 主体 | 预期 |
|---|---|
| 匿名 | 除明确公开功能外拒绝，不泄露敏感信息 |
| Overall/Read | 不能配置、枚举全局凭据、读控制器文件或任意外连带凭据 |
| Item/Read | 不能 input/build/configure，除非权限语义明确允许 |
| 全局 Item/Configure、无具体 Item 权限 | 不能操作被拒绝的具体 Item |
| Folder A 配置者 | 不能使用 Folder B/System 的未授权凭据或对象 |
| 目标 Item 授权配置者/构建者 | 允许操作作为正对照 |

CSRF 增加 GET、POST 无 crumb、有效 crumb；嵌套授权增加无父 Folder Read 但有子 Item Read；缓存增加同 ID 不同 Folder。

## 5. 安全 PoC 设计

- 使用 `attacker@example.invalid` 等合成身份、临时 Folder/Job 和一次性秘密。
- SSRF/凭据捕获用回环伪 HTTP 服务，仅证明收到的认证材料属于合成凭据；禁访问云 metadata 和内网。
- 文件 oracle 用自行创建的临时文件，不探 `/etc/shadow`、用户目录或真实 config 秘密。
- 文件写删只在测试临时目录，路径越界目标也是测试拥有的无害文件。
- sandbox/脚本只写临时标记或返回固定值，不执行系统命令、不加载外部 JAR。
- 每次测试后恢复全局权限策略、脚本审批、凭据和 Job；不连接生产 Jenkins。

## 6. 判定规则

`confirmed`：真实目标代码被执行，未授权主体触发预期安全影响，授权/无权限/安全对照符合预期。记录请求、响应、日志或状态变化。

`likely`：源码链完整但环境或动态条件未满足。说明具体缺什么，不能写“已复现”。

`uncertain`：路由、权限配置、对象解析或关键 sink 未决，且当前证据不能排除。

`false_positive`：路径/snippet 不符、已有 guard、不可达或无安全影响，并给出证据。不要为保留 finding 而改猜新文件。

## 7. 验证记录模板

记录 commit、core/plugin 版本、测试入口、身份矩阵、每步请求/调用、期望与实际、正负对照、清理、未覆盖部署层。明确 Harness 不等于完整 Jenkins，单机不等于分布式 agent，静态不等于动态，ID 枚举不等于秘密明文泄露。
