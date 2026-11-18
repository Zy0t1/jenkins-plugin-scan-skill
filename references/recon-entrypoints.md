# Recon：Jenkins 插件入口与攻击面

## 1. 固定项目画像

先读 `pom.xml`、`.mvn/`、`Jenkinsfile` 和 README，记录 parent/artifactId/version、Jenkins core 版本、插件依赖、Java 版本和 commit。Jenkins 插件常含多维护分支版本，不能只用语义化三段式推断。

再定位：

- `src/main/java/**/*.java`：Descriptor、Action、RootAction、Builder/Recorder、SCM、Pipeline step。
- `src/main/resources/**/*.jelly`：表单字段、校验按钮、下拉框与端点参数。
- `src/main/webapp/`：可直接访问资源及潜在敏感文件。
- `src/test/java/`：已有权限测试、MockAuthorizationStrategy 和 sibling 修复对照。
- `src/main/java/**/*.groovy`、Pipeline CPS/Script Security 相关类（若存在）。

## 2. 枚举 Stapler/Web 入口

搜索并逐个确认路由对象，而不是只统计方法名：

```regex
\b(public|protected)\s+[\w<>\[\], ?]+\s+do[A-Z]\w*\s*\(
doCheck|doFill\w*Items|doValidate|doTest|doSubmit|doConfigSubmit
@(?:RequirePOST|POST|GET|DELETE|PUT|WebMethod|DataBoundConstructor|DataBoundSetter)
extends\s+(?:UnprotectedRootAction|RootAction)|implements\s+(?:Action|RootAction|UnprotectedRootAction)
StaplerRequest|StaplerResponse|HttpResponses|respond|sendRedirect|getTarget|getDynamic
CrumbExclusion|getCrumbExclusion|process\s*\(
```

同时从 Jelly 反向查路由：

```regex
checkUrl=|validateButton|fillDependsOn|with="|field="|credentials|descriptorList
```

将 Jelly 的 field、Descriptor 和 `doCheck<Field>`/`doFill<Field>Items` 对齐。不要假设 Java 搜索能发现所有 URL，也不要假设 Jelly 未引用就不可达。

## 3. 标出敏感 sink

按影响排序，不以“危险 API”直接报漏洞：

- 凭据：`CredentialsProvider`、`findCredentialById`、`lookupCredentials`、`CredentialsMatcher`、`Secret`、`SecretBytes`。
- 网络：`URL.openConnection`、`HttpClient`、`JenkinsLocationConfiguration`、SCM/JDBC/GitLab/GitHub 连接。
- 控制器文件：`File`、`FilePath`、`Files.`、`Files.is*`、`File.exists`、config.xml/build.xml。
- 执行：Groovy/CPS、`ScriptApproval`、`GroovySandbox`、表达式/模板解析、命令执行。
- 状态：job/folder/system config 修改、build/trigger/rebuild/replay/restart、角色和权限修改。
- 信息：节点、用户、已安装插件、schema、凭据 ID、服务器 URL、待审批 classpath。

## 4. 给入口定优先级

P0：Overall/Read、Item/Read 或匿名可达，且连接攻击者 URL、使用凭据、读控制器文件、执行脚本或改权限。

P1：对象级配置/构建操作、嵌套 Folder、全局 Item/Configure 与具体 Item 权限混淆、rebuild/replay/restart 审批。

P2：单纯诊断/schema/ID/内部 URL 泄露；需证明 Jenkins 安全公告级敏感性与可达性才升级。

降级：仅 ADMINISTER 可用的预期管理操作；纯内部私有方法且无外部调用者；测试 fixture；仅在 agent 上执行且没有控制器边界跨越（仍须核实）。

## 5. Recon 交付

输出端点台账和优先文件，不输出 finding。每行至少有：入口方法、路由拥有者、参数来源、祖先对象、敏感 sink、初始身份假设、相邻 guard 和下一审计文件。

完成标准：所有 `do*`、Jelly 校验/填充、RootAction/webhook、构建触发/重放入口均有状态（待审、无敏感操作、已有 guard 或不可达理由），而不是“搜索完成”。
