# AutoCVE FinalizeFinding 与报告契约

## 1. 严格字段

FinalizedFinding 禁止额外字段。每条 finding 仅使用：

```text
vulnerability_type, severity, title, description, file_path,
line_start, line_end, code_snippet, source, sink, suggestion,
confidence, needs_verification, verdict, exploit_chain, poc,
impact, cve_justification, verification_notes
```

顶层仅 `findings`、`summary`，可选 `completion_note`、`needs_handoff`。`severity` 只能 `critical/high`；`verdict` 只能 `candidate/confirmed`；`line_end >= line_start`；confidence 为 0–1。

E1–E5、CWE、commit、身份矩阵等自定义信息不能增加 JSON 键。把根因与证据写进 description/exploit_chain，把版本与新颖性写进 cve_justification，把限制写进 verification_notes。

## 2. JSON 骨架

以下是结构示意，提交时替换为真实证据，不得保留占位符：

```json
{
  "findings": [
    {
      "vulnerability_type": "Missing Authorization",
      "severity": "high",
      "title": "Overall/Read users can enumerate credential IDs through ...",
      "description": "入口、最低攻击者权限、目标对象、应有权限、缺失 guard 与影响。",
      "file_path": "src/main/java/.../DescriptorImpl.java",
      "line_start": 120,
      "line_end": 135,
      "code_snippet": "粘贴目标文件中真实且足够的根因片段",
      "source": "Stapler 路由参数 credentialsId/item 路径及攻击者身份",
      "sink": "CredentialsProvider 枚举/网络/文件/脚本等实际操作",
      "suggestion": "在真实对象上 checkPermission，并按需限制 POST/crumb/作用域",
      "confidence": 0.88,
      "needs_verification": true,
      "verdict": "candidate",
      "exploit_chain": [
        {
          "step": 1,
          "location": "src/main/java/.../DescriptorImpl.java:120",
          "description": "低权限用户请求公开 Stapler 端点。",
          "data_state": "攻击者控制 item 路径或 credentialsId。",
          "bypass_reason": "公开方法及上游未执行目标对象权限检查。"
        },
        {
          "step": 2,
          "location": "src/main/java/.../DescriptorImpl.java:130",
          "description": "敏感操作被调用并返回/产生安全影响。",
          "data_state": "仅描述实际证据支持的数据。",
          "bypass_reason": "无进一步授权或作用域限制。"
        }
      ],
      "poc": {
        "description": "授权测试实例中的最小安全复现。",
        "preconditions": ["固定 commit 与插件版本", "合成低权限用户与合成凭据"],
        "steps": [
          {
            "step": 1,
            "action": "以低权限用户构造目标端点请求",
            "request": "使用脱敏的测试 URL/参数；不要写真实主机与秘密",
            "expected_response": "未授权请求到达 sink；授权对照被拒绝"
          }
        ],
        "payload": "仅放安全、必要、可复现的请求或测试代码",
        "impact": "严格限定为已证明的 ID 枚举、oracle、跨域使用等",
        "cve_justification": "为何可构成安全公告/CVE，以及最低权限与影响"
      },
      "impact": "说明机密性/完整性和跨对象边界，不夸大。",
      "cve_justification": "与相邻 CVE/修复的区别、版本来源、为何不是正常功能。",
      "verification_notes": "E1–E5 覆盖、正负对照、动态验证状态及未覆盖边界。"
    }
  ],
  "summary": "审计覆盖、发现数、未决区域与误报排除概况。",
  "completion_note": null,
  "needs_handoff": true
}
```

`exploit_chain` 至少一步，`poc.steps` 至少一步且每项是对象，不是字符串。`poc` 的 description、impact、cve_justification 必填；verification_notes 也必填。

## 3. 字段写作纪律

- `file_path/line_start` 指向缺失或错误 guard 的根因；sink 在其他文件时写入 exploit_chain。
- `code_snippet` 不得拼接不同区域制造缺失检查，也不得包含真实秘密。
- `source` 同时写入口与攻击者身份；`sink` 写具体安全结果，不只写 API 名。
- `suggestion` 与根因一一对应。缺对象权限不能只加 @POST，CSRF 不能只加权限，cache 混淆不能只隐藏下拉列表。
- `confidence` 反映证据而非影响；高危不自动高置信。
- Finding 的 confirmed 只表示静态证据完整。动态未做时明确 `needs_verification=true`，最终动态状态由 Verification 更新。
- ID 枚举、密文暴露、明文捕获、任意文件读写、controller RCE 是不同影响，不能互相替换。

## 4. 严重度门槛

AutoCVE finalizer 只收 critical/high。一般而言，匿名/Overall/Read 导致可用凭据捕获、controller 文件写读、配置/角色修改、构建或脚本边界突破可优先评估 high/critical；单纯低敏 ID/URL/schema 枚举需结合历史公告与实际利用链谨慎定级。

不因“Jenkins 插件常见”而升级，也不为了提交而把 medium/low 写成 high。无法达到门槛时留在 summary。

## 5. 无发现与失败输出

无合格 finding 时使用：

```json
{
  "findings": [],
  "summary": "已审端点与文件范围、主要已存在 guard、未覆盖/无法解析区域、无高危结论的原因。"
}
```

工具调用失败、目标文件不存在或证据不足不得编造 finding。若 FinalizeFinding 返回 validation error，按字段修正后重新调用，不用普通 Markdown 代替。

## 6. 后续中英/CVE 报告

AutoCVE 报告阶段另用 FinalizeVulnerabilityReports，不要把报告字段混入 FinalizeFinding。报告至少包含 Summary、Details、PoC、Impact、Remediation、Disclosure Notes、Affected products、CVSS、CWE 和 suggested CVE description；代码片段与 PoC 必须来自本次真实证据。

报告明确区分：静态推导、JenkinsRule、最小 Harness、完整部署；验证过的影响与未验证的后续影响；当前默认分支与维护分支；已知 CVE 与潜在新根因。
