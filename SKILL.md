---
name: jenkins-plugin-auth-audit
description: Audit Jenkins plugins for Stapler authorization, CSRF, identity propagation, credential scope, and privilege-boundary flaws; aligned with AutoCVE agents and FinalizeFinding.
tags: [jenkins, jenkins-plugin, java, stapler, authorization, csrf, credentials, cve]
when_to_use: Use when reviewing a Jenkins plugin, Jenkins-facing Java/Groovy code, Jelly form validation endpoints, build identity, credential lookup, or Jenkins authorization CVEs.
version: 1.0.0
---

# Jenkins Plugin Auth Audit

面向 Jenkins 插件源码的鉴权漏洞挖掘与验证。目标不是罗列 API，而是让每个候选闭合为“可达入口 → 攻击者身份 → 应有权限 → 实际检查 → 敏感操作 → 对照证据”。

仅在用户授权的源码、测试实例或隔离沙箱中使用。不得对未授权 Jenkins 实例探测、读取真实凭据或修改任务与配置。

## 启动与资源路由

先读本正文，再按当前 AutoCVE Agent 加载资源；不要一次性加载全部 references。

| 当前 Agent | 必读资源 | 任务边界 |
|---|---|---|
| Orchestrator | `references/agent-playbook.md` | 保持平台阶段与合并契约，不另造 Agent |
| Recon | `references/recon-entrypoints.md` | 只建攻击面与优先级，不提交漏洞 |
| Scan | `references/scan-patterns.md` | 产生候选；不得把正则命中当结论 |
| Triage | `references/agent-playbook.md`、`references/triage-verification.md` | 逐条读源码，保留完整 FinalizedFinding |
| Finding | `references/check-authorization.md`、`references/check-csrf-identity.md`、`references/check-credentials-secrets.md`、`references/report-template.md` | 主审计者，闭合链路并调用 FinalizeFinding |
| Verification | `references/triage-verification.md`、`references/report-template.md` | 独立核对文件、代码、身份矩阵和安全复现 |

按需补充：涉及 sandbox、XXE、路径或表达式执行时读 `references/check-execution-boundaries.md`；做版本比对或 CVE 新颖性判断时读 `references/cve-patterns.md`。AutoCVE 中资源路径相对 skill 根目录，例如 `references/check-authorization.md`。

## 对齐 AutoCVE 的真实工作流

当前 AutoCVE `main` 的 Orchestrator 实现为：Recon → Finding → 确定性 ScanPipeline → Triage → 按 `file_path + line_start + vulnerability_type` 合并 → Verification → Finalize。文档图可能把分析阶段画成并行，部署时以本地 Orchestrator 源码为准。

- 推荐“综合审计”；仅开 Finding 也适合本专项。Orchestrator/Recon 始终启用，Triage 依赖 Scan。
- 主绑定 `finding`；可分别绑定 `recon`、`triage`、`verification`。不要把本 skill 当作自动安装到 Semgrep 的规则包。
- Finding 必须通过 `FinalizeFinding` 终止；普通自然语言总结不算有效提交。
- FinalizedFinding 的 `severity` 仅允许 `critical` 或 `high`，`verdict` 仅允许 `candidate` 或 `confirmed`。中低危线索写入 summary，不塞入 findings。
- Verification 使用 `confirmed/likely/uncertain/false_positive`；Orchestrator 再派生报告状态。不要把 Verification 四态写进 Finding 的 finalizer。

## Finding 主流程

### 1. 固定审计基线

记录仓库、分支或 commit、插件版本、Jenkins core baseline、目标文件和排除项。版本只用于界定研究对象，不能代替源码证据。

### 2. 建立端点台账

按 `references/recon-entrypoints.md` 枚举 Stapler `do*`、表单校验/下拉填充、RootAction、webhook、数据绑定及构建触发入口。为每个入口建立一行：

```text
endpoint | caller/auth | target object | expected permission | actual guard |
verb/crumb | source | sink | upstream guard | candidate state
```

敏感操作包括凭据枚举或使用、控制器文件访问、任意外连、脚本执行、任务/配置修改、构建触发和敏感数据返回。

### 3. 逐入口推导“应有权限”

权限由目标对象和操作决定，不由方法名决定。全局配置通常看 `Jenkins.ADMINISTER`（或语义匹配的 `Jenkins.MANAGE`）；任务配置看实际 Item 的 `Item.CONFIGURE`；构建看 `Item.BUILD`/对应 Job 权限；嵌套对象同时核对父 Folder 可见性。不能因为调用者已有 `Overall/Read` 就允许配置、凭据或文件操作。

### 4. 做五类专项检查

1. 缺失、错误或不可阻断的权限检查：重点看 `checkPermission`、被忽略的 `hasPermission`、全局权限代替对象权限、父 Folder 绕过。
2. CSRF 与副作用：GET 状态变更、缺 crumb、危险 form validation、`@POST`/`@RequirePOST` 与权限只具其一。
3. 身份与审批：构建身份丢失、`ACL.SYSTEM`/`ACL.SYSTEM2` 过宽、rebuild/replay/restart 未重新检查脚本审批。
4. 凭据作用域：仅按 ID 查找或缓存，缺 Item/Folder/Run/Authentication 上下文；`EXTENDED_READ` 泄露密文或秘密。
5. 特权边界后的危险 sink：只有能证明鉴权/沙箱/身份边界被跨越时，才把 SSRF、XXE、路径、表达式或 sandbox 问题纳入本专项。

### 5. 做反向证明与 sibling 审查

对每个候选主动寻找上游 interceptor、父类、Descriptor、路由层和权限策略中的检查。阅读同类已保护方法作为对照，并检查同一 Descriptor/Action 的其他端点。一个方法存在正确检查，不代表 sibling 全部安全。

### 6. 达到证据门槛再提交

- E1 可达性：路由真实存在，攻击者身份和最低权限明确。
- E2 权限语义：说明为什么该对象/操作需要更高或不同权限。
- E3 缺口：指出缺失/错误检查，并排除上游保护。
- E4 影响：source 到敏感 sink 的数据与调用链闭合。
- E5 对照：至少一个安全负向用例；动态验证未完成时明确写限制。

Finding 默认 `candidate`。只有静态链路完整且无未决关键前提时才用 `confirmed`；这不等于动态复现。仍需动态确认时设 `needs_verification=true`，并在 `verification_notes` 写明缺口。

### 7. 严格提交与收尾

按 `references/report-template.md` 调用 FinalizeFinding。`code_snippet` 必须来自目标文件，`file_path` 用项目内相对路径，`line_start/line_end` 指向根因而非随机 sink。自定义 E1–E5 字段不能加入 JSON；应融入 description、exploit_chain、poc 和 verification_notes。

无合格发现时提交空 findings，并在 summary 给出已审端点数、覆盖文件、排除理由和未决区域；不得为“有产出”而降低标准。

## 禁止项

不要仅凭危险 API、CVE 编号、NVD affected 区间或正则命中确认漏洞；不要把普通 XSS、TLS、日志遮罩、XXE 或 sandbox bypass 自动命名为鉴权漏洞；不要把 `@POST` 当权限检查，把 `hasPermission` 当自动拒绝，或把凭据加密当作用域授权；不要声称“新 CVE/未修复”而不做上游公告、历史修复和当前源码比对。
