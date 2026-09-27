# SSH 查询服务部署

服务端使用独立的 Go 可执行程序，客户端通过系统的 `ssh` 进入查询界面。客户端不需要安装 Python、PowerShell 7、Go 或项目文件。

## 所需资源

- 一台可管理的 Linux 服务器；一般使用 1 核、1 GB 内存即可起步。
- 公网地址，域名可选。允许客户端访问 TCP 2222，服务器可访问 HTTPS 数据源。
- 管理员 SSH 地址、用户和端口，使用已有 SSH 密钥即可。管理员 SSH 端口与检测服务独立，不修改原有 sshd 配置。

本仓库包含服务端、测试与 systemd 单元，实际服务器地址和部署状态须以部署完成后的说明为准。

## 编译（仅开发/部署机器需要 Go）

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o nodequality ./cmd/nodequality
```

ARM64 服务器将 `GOARCH=amd64` 改为 `GOARCH=arm64`。Go 模块依赖在编译时打入可执行程序，不要求服务器安装 Go 或 libc 兼容运行时。

## 运行

将可执行程序放到 `/opt/nodequality/nodequality`，部署 `deploy/nodequality.service` 到 `/etc/systemd/system/nodequality.service`，然后执行：

```sh
systemctl daemon-reload
systemctl enable --now nodequality
systemctl status nodequality
```

服务使用 systemd 的临时受限用户；只有 `/var/lib/nodequality` 中的持久 SSH 主机密钥需要写入磁盘。服务本身不需要 root 权限。服务器防火墙及云平台安全组需允许 TCP 2222 入站。

也可以直接运行（当前目录须可写，供首次生成主机密钥）：

```sh
./nodequality serve --listen :2222 --host-key ./nodequality_host_key
```

默认最多同时接入 8 个连接，每个连接最长 2 分钟，每个来源 IP 两次查询间隔至少 10 秒。可以使用 `serve --help` 查看配置。

## 客户端统一命令

把 `SERVER_ADDRESS` 换成实际服务器地址后，Windows PowerShell、CMD、Linux/macOS 终端都使用同一行：

```text
ssh -p 2222 check@SERVER_ADDRESS
```

这是公开的**查询账号**，不需要系统账号密码，不提供服务器命令行。首次连接时 SSH 可能要求确认主机指纹；指纹由服务启动日志提供。保留该确认流程，不关闭 SSH 主机校验。

- 手动输入 IPv4/IPv6：查询该 IP。
- 直接回车：查询服务器看到的**本次 SSH 连接来源 IP**；不会使用检测服务器自己的公网 IP，也不会额外访问 IP 自动识别接口。
- 一次查询完成后断开连接，回到用户原来的终端。
- 如果客户端经过代理、VPN、跳板机或 NAT，则默认值是本次 SSH 连接在服务端呈现的出口地址。只能自动识别本次连接的一个地址族；另一个地址可以手动输入。

客户端需要能运行 `ssh` 且能连接服务器。没有 SSH 客户端、离线或禁止出站连接的系统不能使用这个入口。

## 结果与隔离

查询在提供的服务器上执行。服务器收到待查 IP，第三方数据源收到该 IP；报告只通过 SSH 返回客户端。程序不将报告写入文件、日志，不生成公开报告链接，不上传整份报告。服务日志只有启动信息、主机密钥指纹及服务错误。

服务仅接受一个交互查询会话，拒绝 `exec` 命令、SFTP/SCP、端口转发、代理转发和环境变量请求。它使用自己的 SSH 协议处理器，不调用系统 shell，不接入主机的账户登录功能。用户输入只作为 IP 地址验证和查询参数处理。

只保留 IP 基础信息、类型、风险评分、风险因子和两个有对照验证的 DNSBL 查询。流媒体/SMTP 检测不执行。查询失败表示“不可用/未知”，不代表低风险；不同数据源的评分不混合计算。
