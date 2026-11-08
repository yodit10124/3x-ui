# 3x-ui 安全修复说明（基于 v2.9.4，审计清单见 `~/workspace/audit/3x-ui-audit-v2.9.3.md`）

本分支在上游 v2.9.4 基础上修复了审计列出的漏洞。**这不是官方 v3.3.1 的升级**，
官方修复仍建议跟进。构建产物见 `build/`。

## 已修复

| 编号 | 修复 | 文件 |
|---|---|---|
| H1 CVE-2026-55477 | `ValidateXrayLogPath`：只允许空 / `none` / 日志目录（默认 `/var/log/x-ui`）下的 `.log`；先 `Clean` 再比对前缀，`EvalSymlinks` 解析真实路径（含不存在文件时解析父目录）。三处调用：`CheckXrayConfig`/`SaveXraySetting`、导入数据库前（`ImportDB` 替换数据库之前校验）、`xray.Process.Start()` 写 config.json 之前；`GetAccessLogPath` 加类型断言 ok 检查 | `config/config.go`、`database/db.go`、`web/service/xray_setting.go`、`web/service/server.go`、`xray/process.go` |
| H2 | 登录限流：同一 IP 失败 5 次锁定 15 分钟（内存记录）；默认 admin/admin 未改成硬编码口令，成功用默认口令登录时记警告日志 | `web/controller/index.go` |
| H3 | CSRF 中间件：`/panel/api/` 下的 POST/PUT/DELETE/PATCH 要求 `X-Requested-With: XMLHttpRequest`（前端 axios 已发该头），Origin/Referer 存在时须与 Host 一致；`getDb` 由 GET 改 POST（前端改用 fetch + blob 下载）；`backuptotgbot` GET 也要求该头 | `web/middleware/csrf.go`、`web/web.go`、`web/controller/server.go`、`web/html/index.html` |
| H4 | 配置了证书但加载失败时直接返回错误拒绝启动，不再静默回退 HTTP；`webListen`/`subListen` 默认值由空（0.0.0.0）改为 `127.0.0.1`（已有数据库里的旧值不受影响） | `web/web.go`、`sub/sub.go`、`web/service/setting.go` |
| H5 | 登录失败日志不再记录密码原文；TG 登录通知不再附带密码值 | `web/controller/index.go`、`web/service/tgbot.go` |
| H6 | `x-ui.sh` 的 `eval $install_command` 改为直接执行，版本号用 `^[0-9]+\.[0-9]+\.[0-9]+$` 白名单；`install.sh`/`update.sh` 下载 tar.gz 后如设置了 `XUI_TARBALL_SHA256` 则校验，否则警告 | `x-ui.sh`、`install.sh`、`update.sh` |
| M1 | 会话每次请求都到数据库重新校验：用户删除或改密后旧 cookie 立即失效；改密时轮换 cookie 签名 secret（重启后完全生效） | `web/session/session.go`、`web/service/user.go`、`web/service/setting.go` |
| M2 | WireGuard 配置文本在 `v-html` 前先转义 `&<>`；`index.html` 的日志渲染在 v2.9.4 里已转义，未再改 | `web/html/modals/inbound_info_modal.html` |
| M3 | 与 H1 同一套校验；Xray `api` 入站只允许绑 `127.0.0.1`/`localhost`/`::1` | `web/service/xray_setting.go` |
| M4 | `downloadXRay` 版本白名单（`v?x.y.z`），下载失败（非 200）直接报错；有 `.dgst` 时校验 SHA256，不匹配则丢弃文件 | `web/service/server.go` |
| M5 | `GetNewEchCert` 的 sni 只允许合法主机名，拒绝以 `-` 开头等，并用 `--serverName=` 形式传参 | `web/service/server.go` |
| M6 | 订阅端口默认只监听 `127.0.0.1`（与 H4 同一改动）；订阅默认开启未改，SubID 生成逻辑未改 | `web/service/setting.go` |
| M7 | `setting/all` 不再明文返回 `tgBotToken`/`twoFactorToken`（返回 `******` 占位），保存时占位符不会覆盖原值 | `web/service/setting.go` |
| M8 | 已确认无需改：v2.9.4 的 `util/ldap/ldap.go` 已用 `ldap.EscapeFilter` 转义用户名，且 `ldapEnable` 默认 `false` | — |
| L2 | 配置文件写盘 0777 → 0644，崩溃报告 0777 → 0644，Xray 二进制提取 0777 → 0755 | `xray/process.go`、`web/service/server.go` |
| L3 | 增加 CSP、`X-Frame-Options: SAMEORIGIN`、`X-Content-Type-Options: nosniff`、`Referrer-Policy` 响应头（面板与订阅服务） | `web/middleware/csrf.go`、`web/web.go`、`sub/sub.go` |

## 部分修复 / 未修（原因）

- **H2 首次启动强制改密**：未做。改默认口令或强制改密会破坏现有部署的自动化流程；已用限流 + 默认口令警告代替。**部署后第一件事仍是手动改掉 admin/admin。**
- **H6 `curl \| sh`（acme.sh、speedtest 安装脚本）**：未改。上游未提供可校验的哈希，无法在不破坏安装流程的前提下验证；仅对面板 tar.gz 做了可配置校验。
- **M4 SHA256**：Xray 官方 `.dgst` 文件如不存在则只警告、不阻断（见 `verifyXrayZipSHA256` 注释）。
- **L4 `POST /getTwoFactorEnable` 未鉴权**：未改。该接口只返回布尔值，且登录页未登录时就需要调用它来决定是否显示 2FA 输入框；加鉴权会破坏登录页。
- **H3 cookie Secure 标志**：未加。面板默认是 HTTP（无证书时），加 Secure 会导致登录失效；仅在 TLS 启用且反代场景下由反代负责。SameSite=Lax 保持不变。

## 测试

- 新增 `config/config_test.go`（路径白名单、符号链接逃逸、父目录符号链接、非法路径）和
  `database/db_import_test.go`（恶意 `xrayTemplateConfig` 导入被拒绝、正常配置通过、无配置通过）。
- `go vet ./...` 通过；`go test ./config/ ./database/... ./web/service/ ./web/job/` 全部通过。

## 构建

- Go 1.26.2（`~/workspace/tools/go`，GOPATH `~/go`）。
- Linux：`CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o build/x-ui-linux-amd64 .`
  （CGO 必需，sqlite 用 `mattn/go-sqlite3`；注意 `/tmp` 是 512M tmpfs，编 sqlite 时可能写满，
  用 `TMPDIR=$HOME/tmp` 绕过。）
- Windows：`CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -o build/x-ui-windows-amd64.exe .`
  （需 `gcc-mingw-w64-x86-64`；`CGO_ENABLED=0` 无法编译，因 sqlite 需要 CGO。）

## 部署前注意

1. 首次启动后立即改掉默认 admin/admin 口令，并开启 2FA。
2. 不要直接把面板暴露到公网；建议只监听 127.0.0.1 并用反向代理加 TLS 和 IP 白名单。
3. 如配置了 TLS 证书路径但证书损坏，面板现在会拒绝启动（H4），不再静默回退 HTTP。
4. 本次修复不等同于升级到官方 v3.3.1；建议后续跟进官方升级。

## 2026-11-07 白屏回归修复

- 原因：首次修复加的 CSP 是 `script-src 'self' 'unsafe-inline'`，没有 `'unsafe-eval'`。Vue 2.7 的模板编译器用 `new Function(...)` 把 in-DOM 模板编译成 render 函数（`web/assets/vue/vue.min.js` 的 `createFunction`），浏览器按 CSP 拒绝执行，Vue 挂载失败，`#app` 一直被 `v-cloak` 藏着，登录页和管理页全是白屏。服务端其实正常：HTML、登录、API 全部返回 200。
- 验证：用 Playwright + Chromium 131 实测。旧 CSP：页面正文为空，`#app` 高度 0，没有输入框和登录表单，白屏复现；新 CSP：正文 "Hello / Welcome / Log In"，`#app` 高 720，2 个输入框，登录表单正常，控制台 0 报错。
- 修复：`web/middleware/csrf.go` 的 CSP 改为 `script-src 'self' 'unsafe-inline' 'unsafe-eval'`。这是 Vue 2 in-DOM 模板的硬性要求，无法用更严的 CSP 代替；CSP 其余限制（只允许同源、禁止 object、form-action 同源等）保持不变。两个执行文件已按此重新编译。

## 2026-11-08 第二轮修复（复审优先五项，复审报告见 `~/workspace/audit/3x-ui-fixed-reaudit-2026-11-08.md`）

### 1. CSRF 覆盖到 /panel/ 下全部 POST，登出改 POST（复审 M-1、L-3）
- `web/middleware/csrf.go`：CSRFMiddleware 范围从只含 `/panel/api/` 扩大到 `/panel/` 下全部 POST/PUT/DELETE/PATCH（`/panel/setting/*`、`/panel/xray/*`、`/panel/api/*`），仍要求 `X-Requested-With: XMLHttpRequest`，Origin/Referer 存在时须与 Host 一致；GET 不校验（`backuptotgbot` 例外保留）。未登录的 `/panel/api/*` CSRF 失败统一返回裸 404，与 `checkAPIAuth` 的设计一致，不再用 403 JSON 泄露接口存在性；`/panel/setting/*`、`/panel/xray/*`、`/logout`、`/login` 的 CSRF 失败仍返回 403 JSON（它们的鉴权本来就不是 404 隐藏式）。
- `POST /login` 也纳入 CSRF：前端登录走 axios，`axios-init.js` 已发 `X-Requested-With` 头，浏览器登录不受影响（已用 Playwright 实测登录成功）；非浏览器脚本登录今后须自带 `-H 'X-Requested-With: XMLHttpRequest'`，否则 403。
- `GET /logout` 改为 `POST /logout`（`web/controller/index.go`），纳入 CSRF 校验；前端登出调用点（侧边栏 `aSidebar.html`、改密后自动登出 `settings.html`）一律改成带头的 POST。`GET /logout` 现返回 404，不再登出。
- 新增 `web/middleware/csrf_test.go`（12 个用例，全部通过）。

### 2. getRemoteIp 只信任可信反代，否则用 RemoteAddr（复审 H-1）
- `web/controller/util.go`：默认只用 `RemoteAddr`（去掉端口后的 IP），忽略 `X-Real-IP` / `X-Forwarded-For`。只有当直连对端属于 `XUI_TRUSTED_PROXIES` 环境变量（逗号分隔的 IP/CIDR，默认空即不信任任何代理）时才采信转发头；采信 XFF 时从链最右侧向左走，跳过可信代理，取第一个不可信的 IP。`X-Real-IP` 只在无 XFF 且对端可信时使用。
- `web/controller/index.go`：`loginAttempts` map 加过期清理（锁过期或 15 分钟无失败记录的条目在下次访问时删除），防止随机键无限增长。新增 `web/controller/util_test.go`（9 个子测试，全部通过）。
- 实测：默认模式下 5 次失败登录各带不同 XFF，仍按真实连接 IP 计数，第 6 次正确登录返回 429 锁定；`XUI_TRUSTED_PROXIES=127.0.0.1` 时 XFF 才生效，同一 XFF 锁 5 次后该 XFF 被锁、换 XFF 可正常登录。

### 3. 导入校验复用完整 CheckXrayConfig，拒绝触发器/视图，导入后轮换 secret（复审 H-3、H-4、H-7 部分）
- 新增 `config/xray_template.go`：`ValidateXrayTemplateConfig`（保存/导入共用）与 `ValidateXrayRuntimeConfig`（启动用，跳过入站协议规则以免误杀数据库入站），核心校验：log 路径白名单；api 入站 listen 只允许 `127.0.0.1`/`localhost`/`::1`，**空也拒绝**（空在 Xray 里等价于 0.0.0.0）；metrics.listen 非 loopback 拒绝；reverse 的 bridges/portals 非空拒绝；routing 里 `geoip:private` 规则的 outboundTag 不是 `blocked` 拒绝；freedom 出站 `redirect` 非空拒绝；`dokodemo-door` 一律拒绝，`tunnel` 仅限内置 api 入站且地址须为 loopback。放在 `config` 包以避免 `database`/`xray` 与 `web/service` 之间的循环依赖。
- `web/service/xray_setting.go` 的 `CheckXrayConfig` 改为委托给 `config.ValidateXrayTemplateConfig`；`xray/process.go` 的 `Start()` 改为对即将写盘的合并配置调 `ValidateXrayRuntimeConfig`，且 `json.Unmarshal` 失败时不再静默跳过校验，改为拒绝启动。
- `database/db.go`：`ValidateImportedXrayConfig` 改走完整模板校验；新增 `ValidateImportedDBObjects`，导入前枚举 `sqlite_master`，拒绝任何触发器、视图、非白名单表和虚表（白名单为实测的 8 张自有表 + `sqlite_sequence`/`sqlite_stat1`/`sqlite_stat4`）；校验用 `mode=ro&immutable=1` 只读不可变方式打开待导入库，校验后文件 SHA256 不变、无 `-wal`/`-shm`/`-journal` 副文件。
- `web/service/server.go` 的 `ImportDB`：校验通过、替换并 `InitDB` 成功、`RestartXrayService` 成功后强制 `RotateSecret()`，成功消息里提示检查管理员账号（新增 i18n key `pages.index.importDatabaseCheckAccounts`，en_US/zh_CN/zh_TW 已翻译，其余语种缺 key 时只显示基础成功消息）。
- 明确未做：默认 `geoip:private → blocked` 规则被删的检测（与用户自定义最小路由无法可靠区分）；catch-all 规则遮蔽 blocked 规则的检测；除转发类入站与 freedom.redirect 外的完整模板 allowlist（socks/http/mixed 开放代理入站、dns.servers、observatory/fakedns 等字段仍原样透传）。secret 轮换下次面板重启才完全生效（运行中进程仍用启动时加载的 secret），轮换后旧 secret 签发的 cookie 在重启前仍可用（既有 M-2 遗留问题，未改）。
- 测试：新增 `config/xray_template_test.go`，扩展 `database/db_import_test.go`，新增 `web/service/setting_rotate_test.go`（轮换可验证），`web/service/xray_setting_test.go` 追加 `TestCheckXrayConfig`。

### 4. TG 回调第二组 switch 加 isAdmin 校验，sendBackup 只发给管理员（复审 H-2，M-18 顺带）
- `web/service/tgbot.go`：核查确认第二组 switch（约 1657–2078 行）确实在 `if (isAdmin)` 之外。入口处加门禁：非管理员只放行 `client_traffic`、`client_commands` 及 `client_sub_links` / `client_individual_links` / `client_qr_links`（无 email 后缀，或带 email 后缀但通过归属校验），其余管理操作（`get_backup`、`reset_all_traffics_c`、`get_banlogs`、`get_usage`、`add_client*` 等）一律拒绝并返回提示。
- `sendBackup` 入口处用 `checkAdmin(chatId)` 二次校验，非管理员拒绝发文件；定时备份（遍历管理员列表）不受影响。群聊中 chatId 是群 ID，即使管理员触发也不会把整库发进群。
- M-18：`client_sub_links` / `client_individual_links` / `client_qr_links` 带 email 后缀的分支执行前校验该 client 的 `TgID == callbackQuery.From.ID`（管理员除外），用已有的 `InboundService.GetClientByEmail`。TgID 为 0 的老客户端会被普通用户查询拒绝（安全默认，需管理员绑定 TgID 后才能自助查询）。
- 未做自动化测试验证（该包现有测试不覆盖 answerCallback/sendBackup），只有代码审查 + 编译/vet/现有测试通过。拒绝提示复用了已有的 `tgbot.answers.errorOperation` 文案，未新增 i18n key。

### 5. 面板内更新改为下载后校验 SHA256 再执行（复审 H-6）
- `web/service/panel.go` 的 `StartUpdate`（任务所说的 `UpdatePanel` 实际函数名）：删掉 `curl -fLs … | bash` 管道命令，改为先用 30 秒超时、`http.Client` 下载 `update.sh` 到 `os.CreateTemp` 的随机名临时文件（0600 权限），大小上限 1 MiB（三重检查：Content-Length 预检 + `LimitReader` + 读完复核），再校验 SHA256，通过后才用 `bash <本地文件>` 执行；校验失败默认拒绝，不产生可执行文件。`systemd-run` 分支与回退分支结构、环境变量、日志原样保留；启动失败时父进程删除临时文件，启动成功时子 shell 在更新脚本退出后删除（`;` 而非 `&&`，失败也照删）。
- SHA256 来源：上游没有可校验的官方哈希文件（仓库内无 `.sha256` 文件；release 附带的 `.sha256` 是 tar 包的，不是滚动的 `update.sh` 的），未编造任何哈希值。期望哈希来自环境变量 `XUI_UPDATE_SHA256`（64 位 hex，格式不对即拒绝）；**未提供时默认拒绝执行**并返回明确错误（不是只警告继续装）。`update.sh` 是滚动脚本，每次上游提交都会变哈希，更新前需重新核对。
- 未改 `acme.sh`、speedtest、`install.sh`、`update.sh`、`x-ui.sh`。前提：临时文件在系统 `/tmp`，依赖面板 systemd 单元未启用 `PrivateTmp`（已核实无此项），否则更新会失败（失败是安全的：bash 找不到文件即退出）。

## 第二轮验证
- `go vet ./...` 通过，无新错误；`gofmt` 干净。
- `go test -count=1 ./...` 全部通过（config、database、web/service、web/job、web/controller、web/middleware 等；xray、sub 等包无测试文件）。
- Playwright + Chromium 131 真浏览器实测新编 linux 二进制：登录页正常渲染（正文 "Hello / Welcome / Log In"，#app 高 720，2 个输入框，控制台 0 报错）；浏览器填 admin/admin 登录成功，进入面板（Overview/Inbounds/Panel Settings/Xray Configs/Log Out 均显示），控制台 0 报错。
- curl 流程验证：登录不带 `X-Requested-With` 返回 403，带头返回 200；登录后 `POST /panel/setting/all` 不带头 403、带头 200；未登录 `POST /panel/api/inbounds/list` 不带头返回 404；`GET /logout` 返回 404 且会话仍有效，`POST /logout` 带头返回 307 并下发 `MaxAge=-1` 的清 cookie 响应；XFF 两阶段验证见第 2 项。
- 重新编译（CGO 必需）：`build/x-ui-linux-amd64`（83M，ELF，`-v` 输出 2.9.4）、`build/x-ui-windows-amd64.exe`（112M，PE32+）。

## 2026-11-08 订阅默认关闭

- `web/service/setting.go` 的 `defaultValueMap` 里 `"subEnable"` 由 `"true"` 改为 `"false"`；`web/assets/js/model/setting.js` 里 `AllSetting` 的 `this.subEnable` 同步改为 `false`。
- 初始化逻辑不变：`GetAllSetting` 会把缺失的 key 用 `defaultValueMap` 的值补齐，`getString` 查不到库里值时也回落到 `defaultValueMap`，所以新装默认关闭；已有数据库里存的值不受影响，之前开着订阅的不会被这次改动关掉。
- 验证（全新数据库）：面板 2053 正常监听，订阅端口 2096 未监听，`POST /panel/setting/all` 返回 `subEnable: false`。订阅服务在 `sub/sub.go` 的 `Start()` 里 `if !subEnable { return nil }`，关掉后整个订阅服务都不启动，json/clash 子路径也随之关闭。需要用订阅时，在设置页把订阅开关打开即可。
