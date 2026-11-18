# 专项检查 A：权限与对象级授权

## 核心问题

对每个入口分别回答：谁调用、操作哪个对象、做什么、最低需要什么权限、代码在哪里强制拒绝。`Overall/Read` 只表示基本可读访问，不天然授予配置、构建、凭据或控制器文件能力。

## 1. 权限语义矩阵

| 场景 | 常见预期权限（仍需按语义核实） | 常见错误 |
|---|---|---|
| 全局系统配置、连接测试、全局凭据 | `Jenkins.ADMINISTER`；部分管理查看可能是 `Jenkins.MANAGE` | 无检查或只检查 Overall/Read |
| 具体 Job/Folder 配置和表单校验 | 该 Item 的 `Item.CONFIGURE` | 用 Jenkins 全局 `Item.CONFIGURE` 代替对象检查 |
| 触发/参数化构建 | 目标 Job 的 `Item.BUILD`/对应 Job.BUILD | 只读源 Job 权限或完全信任调用者 |
| 查看嵌套 Item | 子 Item 与父 Folder 的可见性链 | 只查子 Item.READ，绕过父 Folder |
| 读取配置 XML | 通常 `Item.EXTENDED_READ` | 把 EXTENDED_READ 扩展成秘密/密文读取权 |
| 节点、脚本、角色、构建重放 | Computer/Script/Run 等对应操作权限 | 用 Overall/Read 或 Item/Read 代替 |

不要机械地在所有端点建议 ADMINISTER。过严修复可能破坏功能，过松则留洞；引用同类受保护端点和 Jenkins 开发文档确定语义。

## 2. 检查是否真的阻断

正向信号通常是：

```java
Jenkins.get().checkPermission(Jenkins.ADMINISTER);
item.checkPermission(Item.CONFIGURE);
```

`checkPermission` 在拒绝时抛异常。`hasPermission` 只返回布尔值，以下写法不是保护：

```java
item.hasPermission(Item.CONFIGURE); // 返回值未使用
```

正确形式必须显式 `if (!hasPermission(...)) throw ...` 或等价拒绝。也要防 catch 后忽略 AccessDeniedException、只记录日志继续执行。

## 3. AncestorInPath 与空上下文

`doCheck*`/`doFill*Items` 常通过 `@AncestorInPath Item item`、`Job job`、`AbstractProject` 或 `ItemGroup` 获取对象。审计：

- 参数是否可能为 null；null 时是否进入全局配置分支并检查全局权限。
- 传入对象是否真是 URL 对应目标，还是可由攻击者替换。
- `doFillCredentialsIdItems` 是否在枚举前检查 item/全局权限。
- 静态 helper 被多个 HTTP 方法调用时，是否每个公开入口都保护，而不是只保护其中一个。

## 4. 全局权限不等于对象权限

`Jenkins.get().hasPermission(Item.CONFIGURE)` 与 `item.hasPermission(Item.CONFIGURE)` 语义不同。矩阵/角色授权插件可能授予全局 Item/Configure，但用户在具体 Job 上并无配置权。必须沿实际 ACL/AuthorizationStrategy 求值，不以变量名推断。

代表 CVE-2025-24397：全局 Item/Configure 被错误用于凭据枚举。类似地，CVE-2021-21623 与 CVE-2021-21624 表明子 Item/Read 不能绕过父 Folder 的读取限制。

## 5. 构建身份与系统身份

遇到 `ACL.impersonate(ACL.SYSTEM)`、`ACL.SYSTEM2`、`ACL.as`、`Tasks.getAuthenticationOf`、`Authentication` 传递时，画出身份变化。系统内部任务可能需要 SYSTEM，但外部请求不能直接继承该身份来选目标 Job、凭据或文件。

检查系统身份作用域是否 try-with-resources/finally 限定，是否在恢复用户身份后才执行权限判断。不要把 SYSTEM 的出现本身报为漏洞；必须证明它让攻击者跨过具体操作权限。

## 6. RootAction 与 webhook

`UnprotectedRootAction` 表示无需 `Jenkins.READ` 也可访问，本身不代表匿名全权可用，也不代表 crumb 豁免。匿名 SCM notify、GitHub/GitLab webhook 若另有 `CrumbExclusion` 或相关 interceptor，才需沿该路径检查 CSRF 处理；无论是否豁免 crumb，都要检查独立 token/签名、目标对象解析、重放保护和目标 Job 权限。URL 含随机 token 也要验证 token 比较、绑定对象和泄露风险。

CVE-2018-1000110 与 CVE-2018-1000111 是网络可达端点泄露节点/用户的代表，不应只关注带 Descriptor 的表单方法。

## 7. 常见高价值模式

- `Overall/Read → doFillCredentialsIdItems → 凭据 ID 枚举`：CVE-2019-10342、CVE-2021-21625、CVE-2022-20618、CVE-2022-20620、CVE-2022-30955、CVE-2022-43413。
- `Overall/Read → 攻击者 URL + 指定 credential ID → 捕获凭据`：CVE-2018-1000412、CVE-2019-1003043、CVE-2020-2234、CVE-2026-42522。
- `Overall/Read → 凭据类型/元数据 oracle`：CVE-2022-20616 可判断 credential ID 是否指向 secret file 及是否为 ZIP，不是任意控制器路径存在性。
- `Overall/Read → 控制器文件存在性 oracle`：CVE-2024-52549、CVE-2025-58458。
- `Item/Read → input 交互`，实际应要求 Item/Build：CVE-2017-1000108。

## 8. 负向排除

明确记录并定位以下反证：父类已检查、统一 interceptor 已保护、路由根本不可达、只对管理员展示且服务端仍校验、操作本无安全边界、sink 在隔离 agent 而非 controller、参数不可控。UI 隐藏按钮不是服务端权限检查。
