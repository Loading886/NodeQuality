# NodeQuality · IP 质量查询

仅保留 IP 质量查询，支持手动输入任意公网 IPv4/IPv6。硬件测试、网络测速、回程路由和整份报告上传均已移除。

## 跨系统使用完全相同的一行命令

通过专用 SSH 查询服务，Windows PowerShell、CMD、Linux 和 macOS 终端可以使用相同的入口：

```text
ssh -p 2222 check@SERVER_ADDRESS
```

**当前需要提供服务器并完成部署，`SERVER_ADDRESS` 是占位符，尚不是可直接连接的地址。** 服务端代码、测试及部署单元已包含在仓库中。

客户端只需系统已有的 `ssh`，不需要 Python、PowerShell 7、Go、Docker 或下载本项目。没有 SSH 客户端、离线或被网络策略限制的环境仍无法使用；不承诺任何裸系统都能运行。

启动后提示：

```text
输入你要检测的 IP，直接回车检测本次 SSH 连接的来源公网 IP：
```

- 输入 IP：查询指定 IPv4/IPv6。
- 直接回车：查询本次 SSH 连接的来源公网 IP，**不会误测服务器自己的 IP**。
- 结果返回当前终端，查询完成后断开 SSH；不会上传报告或生成公开报告链接。

服务器负责访问数据源，客户端负责显示报告。遇到 VPN、代理、跳板机或 NAT，默认 IP 是服务器看到的连接出口。本次连接只能自动识别一个 IPv4 或 IPv6 地址；其他地址可以手动输入。

## 部署资源

需要一台能管理的公网 Linux 服务器（1 核、1 GB 内存可起步），允许 TCP 2222 入站和 HTTPS 出站；域名可选。服务端是独立可执行程序，不需要 Python 或 Go 运行时。管理 SSH 与查询服务使用不同端口。

完整步骤、运行参数和 systemd 配置见 [SSH 服务部署说明](docs/server.md)。查询账号只运行本工具，拒绝系统命令、文件传输和转发。

## 查询范围与隐私

保留基础信息、ASN、机构/使用类型、风险评分、代理/VPN/Tor/机房/滥用/机器人标记，以及 Spamhaus/SpamCop 两个带对照验证的 DNS 黑名单查询。

数据源包括 MaxMind、IPinfo、Scamalytics、ipapi、AbuseIPDB、IP2Location、ipdata 和 IPQS。部分接口可能限流或返回 403，缺失值显示“未知/不可用”，不当作零分或低风险；各来源的不同评分不会合并。

流媒体/AI 解锁、SMTP 连通性和仅查询请求出口的 DB-IP 接口不执行。公网信誉查询不适用于内网、回环、组播等地址；这些地址不会被发送到外部数据源。

SSH 服务器会收到待查 IP，第三方接口也会收到这个 IP。**整份报告只通过 SSH 返回，不写入服务端文件或日志，也不上传到报告/截图网站**。没有广告或使用次数统计请求。

## 开发与兼容入口

```sh
go test ./...
go vet ./...
go build -o nodequality ./cmd/nodequality
./nodequality serve --listen :2222 --host-key ./nodequality_host_key
```

Go 只用于编译开发。自动检查覆盖 Windows、Linux、macOS，并构建不依赖 libc 的 Linux AMD64/ARM64 服务程序。

已有的本地 Python/Bash 和 PowerShell 7 入口暂时保留，使用方法移至 [原有本地入口](docs/legacy-launchers.md)。它们不是这里的统一 SSH 入口。

基于 [Loading886/NodeQuality](https://github.com/Loading886/NodeQuality) / [LloydAsp/NodeQuality](https://github.com/LloydAsp/NodeQuality)，数据库字段映射参考 [xykt/IPQuality](https://github.com/xykt/IPQuality)。沿用 [AGPL-3.0](LICENSE)；编译依赖的许可证见 [第三方声明](THIRD_PARTY_NOTICES.md)。
