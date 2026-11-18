# AutoCVE Agent Playbook

## 安装与绑定

将整个 `jenkins-plugin-auth-audit/` 目录复制到 AutoCVE 的 `skill_library/`，在 Skills 管理中同步本地目录。主绑定 Finding；Recon、Triage、Verification 可按需绑定。关键词建议：`jenkins`、`jenkins-plugin`、`stapler`、`authorization`、`permission`、`csrf`、`credentials`、`folder`、`build-authentication`。

不要在 skill 内伪造 `agents/<agent>/bindings.json` 并声称已生效。AutoCVE 的绑定位于 skill_library 根下的 `agents/<agent>/bindings.json`，由 UI 或现有绑定机制维护。`always_include` 仅对 Jenkins 专项任务开启，通用审计可依靠关键词匹配。

## Orchestrator

不增加自定义 Agent，不绕开平台 FinalizeFinding/Triage 工具。为任务提供插件名、版本、commit、目标和排除项，优先综合审计。当前实现按 Finding → Scan/Triage 顺序执行分析分支，不要根据架构图假设并行。

合并键是 `file_path + line_start + vulnerability_type`。因此同一根因使用稳定路径、根因行和类型名；真正不同的权限缺口不要故意合并。若同一端点同时缺权限与 CSRF，可分别报告的前提是两者能独立成立、修复和影响不同；否则合并为一个复合 finding。

## Recon

只输出项目画像、入口、优先路径和扫描建议。除通用 Recon 字段外，在摘要或 handoff 上下文尽量交代：

- 插件 artifactId、版本、Jenkins core baseline、构建工具和目标 commit。
- Descriptor/Action/RootAction、Stapler 路由、Jelly `checkUrl`、webhook、构建触发与重放入口。
- 凭据、网络、控制器文件、脚本、配置修改等敏感 sink 所在文件。
- `@AncestorInPath` 可空上下文、全局/Item/Folder 权限边界和 crumb exclusion。

没有漏洞证据时不要生成 finding。将“仅 Overall/Read 可达 + 高影响 sink”的文件置前。

## Scan

当前主链路是确定性 SemgrepScan；本 skill 的检索式只是候选种子，不会自动进入 ScanPipeline。若部署允许自定义规则，先验证规则语法和 Java 解析，再运行并保存规则版本。

扫描输出只回答“哪里值得看”。每个候选至少保留文件、行、匹配原因和相邻 guard 搜索状态。不要把“缺少 checkPermission 的方法”直接定为漏洞；私有方法、测试代码、不可达方法和已有上游检查均可能误报。

## Triage

遵循平台批次协议：GetTriageBatch(batch_size=5) → 对每个 ID 调 GetScanFinding → Read/Grep/Glob 查源码 → FinalizeTriageBatch 覆盖本批每个 ID → 全部完成后 FinalizeTriage。

决策使用平台支持的 `keep/false_positive/duplicate/low_value/needs_more_context/error`。`keep` 必须附完整 FinalizedFinding，且仅保留 critical/high。优先检查：

1. 路由能否被低权限或匿名调用，参数能否由攻击者控制。
2. 应有权限是否由目标对象和操作推出，而非机械要求 ADMINISTER。
3. `hasPermission` 是否真正阻断，父类/拦截器/Descriptor 是否已保护。
4. `@POST` 与权限是否混淆，GET 是否真有副作用。
5. source→sink 是否闭合，凭据 ID 枚举能否造成公告级影响。

误报必须给出具体保护位置或不可达理由；证据不足用 `needs_more_context`，不要猜测。

## Finding

以“一个入口 + 一个对象权限语义 + 一个影响链”为审计单元。先读入口完整方法，再向调用方、被调方、父类、路由和 Jelly 双向追踪。每轮保留端点台账，避免只搜敏感 API 而忽略 Web 暴露面。

同一 sink 有多种输入路径时逐路径验证。对依赖 `@AncestorInPath` 的 Descriptor 表单端点，全局配置和 Item 上下文分别分析；`item == null` 在该语义下通常进入全局配置权限分支，但空祖先本身不证明端点属于全局配置，仍需结合 Descriptor 与路由确认。嵌套 Folder、全局 Item/Configure 与具体 Item/Configure、系统身份与用户身份必须作为不同测试主体。

完成前执行一次反证：尝试用已有 guard、不可达、无敏感影响、仅管理员可用或重复 CVE 推翻候选。无法推翻才 FinalizeFinding。

## Verification

验证者不应只接受发现者结论。先按 finding 的精确路径和行读取，核对 snippet、commit 与调用链；再选择 JenkinsRule 集成测试、最小 Java harness 或静态复核。动态优先，但不能为运行而替换掉被测的权限逻辑。

身份矩阵至少覆盖匿名、Overall/Read、无对象权限用户、全局 Item/Configure 但无具体 Item 权限、对象授权用户；Folder 漏洞另加父/子 Folder 与跨 Folder 用户。CSRF 另加 GET、POST 无 crumb、POST 有效 crumb。

PoC 使用合成凭据、临时文件和本地伪服务。不得读取真实秘密、访问云元数据、扫描内网或对公共实例测试。记录实际覆盖的权限和副作用，不把 mock 成功扩大成完整 Jenkins 部署影响。

Verification verdict：`confirmed` 为动态证据明确；`likely` 为静态链明确但动态未完成；`uncertain` 为关键前提未决；`false_positive` 为代码/路径不符或保护已存在。按平台要求，不存在或 snippet 不匹配的文件不得改猜路径后宣称确认。

## 报告与交接

Verification 保留原 finding 字段并补充 verdict、confidence、is_verified、verification_method/details、实际 PoC、影响与建议。`likely/uncertain` 不得写成已复现。最终报告必须区分源码推导、Harness、JenkinsRule 和完整部署验证的边界。
