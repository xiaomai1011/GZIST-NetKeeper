# R2 + EdgeOne 下载源与自动更新

下载域名为 **https://dl2.nerv-base.com**，链路为：

```text
用户 / MyGo 更新器 → dl2.nerv-base.com（EdgeOne）
                  → origin-dl2.nerv-base.com（R2 自定义域名）
                  → gzist-github-release 桶
```

GitHub Release 保留原始发布附件，作为备用下载渠道。此支持采用 MyGo v0.3.3 官方构建期 `updates.url`，不是运行时代理切换，也没有失败后自动切换公共代理。

> 初次部署使用 GitHub 原版 v2.0.1 作为验证基线，已通过有效 HTTPS、27 个文件及根页面字节校验。**从 v2.0.2 起，新构建包含登录错误处理修复并使用该更新源**；原版 v2.0.1 仍内置 GitHub 地址，需要过渡更新或手动安装新版。修改源配置不会改变旧安装包。正式推广仍需校内实际验收。

## 服务与费用边界

- EdgeOne 免费版的 [使用限制](https://edgeone.ai/document/70405) 不允许大文件分发等用途，没有明确的文件大小阈值。不能把不限流量理解为允许任意软件分发或提供可用性保证；本部署按维护者确认继续使用该路线，仍可能被限制或暂停。未购买升级或增值服务。
- [R2 定价](https://developers.cloudflare.com/r2/pricing/) 中出口流量免费，但超出免费额度的存储和请求仍可能计费。EdgeOne 缓存不是费用硬上限；源站自定义域名也可被直接访问。应监控 Cloudflare 用量和账单，发现滥用可暂停下载域名/源站公开访问。
- EdgeOne 回源使用 HTTPS；免费版不支持配置回源证书真实性校验，默认未启用，不能将加密回源描述为已验证源站身份。见 [官方说明](https://edgeone.ai/document/74344)。客户端访问下载域名仍必须验证 HTTPS 证书，更新归档仍验证固定公钥签名。
- 只对 `dl2.nerv-base.com` 建立规则，不修改同站点的其他域名或全局策略。

## 云端配置

1. 在既有 R2 桶 `gzist-github-release` 的 Settings → Custom Domains 绑定 `origin-dl2.nerv-base.com`，等待 Active。此绑定需要桶管理权限；仅对象读写令牌不能执行。
2. EdgeOne 加速域名 `dl2.nerv-base.com`，源站和 Host Header 均为 `origin-dl2.nerv-base.com`，HTTPS 443 回源。
3. Cloudflare DNS 中 `dl2` 为 **DNS only** CNAME，值使用 EdgeOne 分配的 CNAME，不能再次开启 Cloudflare 代理。
4. 申请并等待 EdgeOne 免费托管证书生效。自动验证未完成时使用 DNS 委派验证：`_dnsauth.dl2` 为 DNS-only CNAME，指向 EdgeOne 返回的 `dl2.nerv-base.com.eoacme0.com`；保留此记录供后续验证。通过 `CheckFreeCertificateVerification` 后，以 `eofreecert_manual` 部署证书。证书不匹配或仍在申请时，不改用 HTTP、不关闭证书验证、不切换客户端更新源。
5. 域名专用缓存规则：
   - 一般内容遵循源站 Cache-Control；缺少该头时不缓存。
   - 忽略全部查询参数、保留路径大小写；本源的文件内容不由查询参数决定。
   - 禁用离线缓存和缓存预刷新，防止继续提供过期更新信息。
   - `/`、`/index.html`、`/install.sh`、`/SHA256SUMS`、六个 `/update-*.json` 精确路径不缓存。
   - 仅 `/` 回源重写为 `/index.html`；HTTP 301 跳转 HTTPS。

源站必须直接提供文件，不能 302 回 GitHub，也不能降级到 HTTP。MyGo v0.3.3 未独立强制禁止 HTTPS 降级重定向，发布校验因此拒绝所有跳转。

## 从完整 Release 生成并上传静态源

使用待部署版本的源码配置；[mygo.json](<../mygo.json>) 的 version 必须与附件一致：

```sh
gh release download vX.Y.Z --repo xiaomai1011/GZIST-NetKeeper --dir release-assets
go run ./tools/releasefeed -assets release-assets -out release-feed \
  -base-url https://dl2.nerv-base.com
```

输出目录必须不存在，其父目录必须存在。生成工具不会联网、修改文件签名或自动部署。它会：

- 要求 macOS、Windows、Linux 的 amd64/arm64 共六份清单与配置版本一致、当前归档文件名匹配目标、六个安装包及脚本齐全；
- 使用固定公钥核验全量归档和增量包的长度及 Ed25519/SHA-256 签名；损坏、缺包、错误签名会失败；
- 将全量和增量 URL 改为下载域名，保留本地可用的历史归档引用，去掉缺失的 `previous` 历史；
- 生成无需 GitHub API 或 JS 的静态下载页，以及包含页面的 `SHA256SUMS`。

将以下环境变量在**本机安全环境或 CI secrets** 中提供，不要把值写入命令历史、源码或聊天：

```text
R2_ACCOUNT_ID
R2_BUCKET
R2_ACCESS_KEY_ID
R2_SECRET_ACCESS_KEY
```

```sh
# 正常发布只接受比当前六份公网清单更新的稳定版本；初次部署基线另行核准。
go run ./tools/feedcheck -mode upgrade -version X.Y.Z -base-url https://dl2.nerv-base.com
go run ./tools/r2publish -dir release-feed -payloads-only
go run ./tools/feedcheck -dir release-feed -base-url https://dl2.nerv-base.com -payloads-only
# 公网包校验通过后，才更新控制文件；已上传的相同版本化包只做 HEAD 复核。
go run ./tools/r2publish -dir release-feed
go run ./tools/feedcheck -dir release-feed -base-url https://dl2.nerv-base.com
```

上传器只访问由账户 ID 确定的官方 R2 S3 HTTPS 端点，不创建桶、不删除对象、不跟随跳转。上传前检查全部文件的校验和、完整性、普通文件类型及安全文件名。版本化包按以下规则处理：

- 已存在：只有长度和 SHA-256 元数据一致才跳过；不覆盖内容不同的同名文件。
- 不存在：使用 `If-None-Match: *` 条件上传，防止并发覆盖。
- 先上传并 HEAD 核验全部版本化包，再上传脚本、六份清单、校验列表和下载页。HEAD 核验的是对象长度和哈希元数据，公网步骤另外下载并核验实际字节。
- 新版本化包为一年 immutable 缓存；可变控制文件为 `no-cache, max-age=0, must-revalidate`。所有新 PUT 均加 `no-transform`，防止 Cloudflare 自动脚本注入等内容改写破坏字节校验。已有相同的 immutable 对象不会为更新头信息而被覆盖。

六份清单不是跨对象原子事务；中途失败可能暂时让不同平台看到不同版本，但按上述流程，每份已公开清单的包已经通过公网字节校验。若控制文件已部分发布，正常 CI 的版本门禁会拒绝同版本重跑：维护者应检查现场状态，使用保存的**同一份 staging artifact**人工补齐并重新验证，而不是重建或绕过门禁直接覆盖。不要在旧标签上重建后覆盖同版本包，不要将旧版本重新部署为 latest；修复发布应增加版本号。

## 仓库与发布流水线

目标仓库为 `xiaomai1011/GZIST-NetKeeper`。它与开发目录的 `origin` 不一定相同，使用 `gh` 时显式加 `--repo`。

GitHub Actions 配置：

| 类型 | 名称 | 用途 |
|---|---|---|
| Secret | `MYGO_UPDATER_PRIVATE_KEY` | 保留现有更新签名私钥 |
| Secret | `R2_ACCESS_KEY_ID` | 桶对象读写凭据 |
| Secret | `R2_SECRET_ACCESS_KEY` | 桶对象读写凭据 |
| Variable | `R2_ACCOUNT_ID` | R2 账户 ID |
| Variable | `R2_BUCKET` | `gzist-github-release` |

EdgeOne 和 Cloudflare DNS 管理密钥不需要放进 CI。R2 凭据应限于此桶的对象读写权限。已在聊天或日志中暴露的凭据应轮换；轮换 R2 后同步更新仓库 secrets。

[release.yml](<../.github/workflows/release.yml>) 的新流程为：

1. 检查标签、版本、测试、签名私钥、R2 配置及可信更新地址。只接受 `X.Y.Z` 稳定版本，且必须大于当前六份公网清单；拒绝已公开 GitHub Release 的重跑。
2. 构建六目标并签名，只上传 GitHub 草稿。
3. 下载完整附件并核验；为 GitHub 原始附件单独生成校验列表。
4. 保存 `release-feed-vX.Y.Z` Actions artifact（14 天）。
5. 再次检查公网版本顺序；仅上传版本化包到 R2。
6. 从 EdgeOne 公网 HTTPS 地址取回版本化包并逐字节校验；失败时不会发布新清单。
7. 发布控制文件，再校验全部 staging 文件和根页面，拒绝跳转、HTTP 降级或内容改写。
8. 以上成功后才发布 GitHub Release。

发布工作流使用共享 concurrency 组，避免不同标签并发写 latest。向目标仓库推送与配置版本匹配的新 `vX.Y.Z` 标签才会触发发布；只推送 main 不发版，已有 Release 不会自动重跑。版本门禁通过公网清单检查发布顺序，因此同版本或降级标签不会覆盖当前源。

## 客户端迁移

当前源码已在 HTTPS 链路验证通过后配置好后续构建；重新配置其他可信域名时使用：

```sh
go run ./tools/releasefeed -mode configure -base-url https://dl2.nerv-base.com
```

这会删除 `updates.github`、写入 `updates.url`，保留 `updates.publicKey`。检查差异后提交。地址会编入新客户端，校园网认证请求不受影响。

旧 GitHub 源客户端须通过 GitHub 拿到一次过渡更新，或手动安装新发布的镜像构建。**只从镜像下载原版 v2.0.1 不会改变它内置的更新地址。** 恢复 GitHub 源同样需要重新构建和交付。

自动更新使用 `https://dl2.nerv-base.com/update-windows-amd64.json` 等六份清单。安装包标签 `x64` 对应清单 `amd64`，不可互换命名。

## 安全与验收

- 清单本身未签名；MyGo 签名不绑定显示版本。可信托管和访问控制仍然必要。
- 普通安装包及安装脚本不受 MyGo 归档签名保护；同站哈希只能检测传输损坏，不能证明来源可信。
- Linux 建议下载匹配架构的归档和脚本，核验来源和哈希后执行 `sh install.sh ./对应架构.tar.gz`。旧版脚本的在线安装仍可能访问 GitHub，不要对第三方镜像 `curl | sh`。
- `.deb` / 无写权限安装不保证有内置更新通知，请由包管理器或手动下载安装升级。
- 本机公网验收不能代替校内实际测试：至少测试 Windows x64 安装、清单访问、全量更新、一次增量更新、网络中断重试和本次登录修复。
- 无 SLA 或校园网速度保证；保留 GitHub 备用入口，监控 TLS 证书、更新清单、存储和请求用量。
