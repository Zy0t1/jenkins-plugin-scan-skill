# Scan：候选检索与 Semgrep 使用边界

这些检索式用于建立候选集，不是漏洞规则，也不会被 AutoCVE 的确定性 ScanPipeline 自动加载。所有命中必须由 Finding 或 Triage 读完整方法、调用方和防护代码。

## 1. 分层检索

第一层找公开入口：

```regex
\bdo(?:Check|Fill|Test|Validate|Submit|ConfigSubmit|[A-Z])\w*\s*\(
@(?:RequirePOST|POST|GET|PUT|DELETE|WebMethod)
UnprotectedRootAction|RootAction|CrumbExclusion
```

第二层找权限和请求防护：

```regex
checkPermission|hasPermission|hasAnyPermission|checkAnyPermission
Jenkins\.ADMINISTER|Jenkins\.MANAGE|Item\.CONFIGURE|Item\.BUILD|Item\.EXTENDED_READ
@RequirePOST|@POST|ACL\.(?:SYSTEM|SYSTEM2)|ACL\.impersonate|ACL\.as
```

第三层找敏感 sink：

```regex
CredentialsProvider|findCredentialById|lookupCredentials|SecretBytes
openConnection|HttpClient|FilePath|new File|Files\.|ScriptApproval|GroovySandbox
trigger|scheduleBuild|replay|rebuild|restart|config\.xml|build\.xml
```

高价值候选是入口和 sink 在同一调用链、但第二层缺失或语义错误。只命中 sink 的私有方法不优先。

## 2. 反向检索已保护 sibling

对同类 `doCheck/doFill/doTest` 搜索 `checkPermission` 和 `@POST`，找一个正确实现作对照。再检查：

- 父类或 BaseDescriptor 是否统一检查。
- 注解是否加在真正暴露的 override 上。
- helper 是否仅由已保护方法调用，还是也被未保护公开端点复用。
- Jelly 的 `checkUrl` 是否与服务端实际方法一致。

## 3. Semgrep 规则种子（需人工适配）

可用以下思想编写 Java 规则，但不要未经验证直接当作生产规则：

```yaml
# 思路 A：doFill...Items 方法体直接调用 CredentialsProvider，且方法内无权限检查。
# 思路 B：doCheck... 方法使用 @AncestorInPath Item，但 item.checkPermission 缺失。
# 思路 C：公开 do... 方法调用 trigger/config update，且无 @POST/@RequirePOST。
# 思路 D：hasPermission(...) 作为独立表达式语句，返回值未参与拒绝。
```

实际规则需处理跨函数、注解继承、父类 guard 和 null 全局分支；Semgrep 单方法 pattern 很难独立证明。建议规则只产出 low-level candidate，由 Triage 决定，不为命中自动赋 high/critical。

## 4. 候选去重

扫描器可能同一根因报入口、helper、sink 三行。Triage 前按“公开入口 + 缺失 guard + sink 语义”聚类，保留根因位置；但不同公开入口分别可达且需分别修复时不要误删。

AutoCVE 最终合并仍按 `file_path + line_start + vulnerability_type`，因此提交前统一根因行和类型名，避免 Finding 与 Scan 各留一份。

## 5. 扫描覆盖摘要

记录扫描文件数、Java 解析失败、排除目录、规则版本和未覆盖的 Jelly/RootAction/webhook。Semgrep 零命中不代表无鉴权漏洞；本专项的主发现路径是 Finding 直接源码审计。
