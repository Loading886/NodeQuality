# NodeQuality · IP 质量查询版

此分支只保留 IP 质量查询。硬件测试、网络测速、回程路由、BenchOS、swap、自动截图和报告上传均已移除。

## 一行运行

在 Linux/macOS 的 Bash 终端中，从任意目录运行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Loading886/NodeQuality/ip-quality-only/NodeQuality.sh)
```

脚本提示：

```text
输入你要检测的 IP，直接回车检测本机 IP：
```

- 输入 IPv4 或 IPv6：查询这个 IP，无须登录目标服务器，也不要求这个 IP 绑定在本机。
- 直接回车：识别本机公网 IPv4/IPv6，查询可用的地址；只有 IPv4 的主机也能正常运行。
- 输入有误：重新提示，不会静默改查本机。

运行需要 **Bash、curl 和 Python 3.9+**，不需要 root、pip 包或克隆仓库。缺少 Python 时脚本会提示，不自动安装系统软件。
`NodeQuality.sh` 内嵌完整查询程序，不依赖当前目录和其他项目文件，不运行远程下载的子脚本。
Windows 可以通过 Git Bash 使用上面命令，或下载后运行 `python ip_quality.py`。

请使用上面的分支地址。原来的 `run.NodeQuality.com` 仍然是原版，与本分支无关。

## 带参数运行

```bash
# 直接查询指定 IPv4
bash <(curl -fsSL https://raw.githubusercontent.com/Loading886/NodeQuality/ip-quality-only/NodeQuality.sh) -i 1.1.1.1

# 查询指定 IPv6：本机不必具备 IPv6 出口
bash <(curl -fsSL https://raw.githubusercontent.com/Loading886/NodeQuality/ip-quality-only/NodeQuality.sh) -i 2606:4700:4700::1111

# 不经提示，直接检测本机公网 IP
bash <(curl -fsSL https://raw.githubusercontent.com/Loading886/NodeQuality/ip-quality-only/NodeQuality.sh) --local

# 下载到本地，之后重复使用
curl -fsSLo NodeQuality.sh https://raw.githubusercontent.com/Loading886/NodeQuality/ip-quality-only/NodeQuality.sh
bash NodeQuality.sh

# 可选：保存 JSON 或纯文本至本地；不覆盖已有文件
bash NodeQuality.sh -i 1.1.1.1 -o ip_quality.json
bash NodeQuality.sh -i 1.1.1.1 -o ip_quality.txt
```

其他参数：`-j` 仅在标准输出打印 JSON；`-E` 使用英文报告；`--timeout 10` 设置单次请求超时；`--no-dnsbl` 跳过 DNS 黑名单；`-h` 查看帮助。

使用交互模式时请保留 `bash <(curl ...)` 的写法，不要用 `curl ... | bash` 占用标准输入。无人值守运行请显式指定 `-i IP` 或 `--local`。

## 检测内容与边界

保留基础信息、ASN、机构/使用类型、风险评分、代理/VPN/Tor/机房/滥用/机器人标记和 DNS 黑名单查询。

数据源包括 MaxMind、IPinfo、Scamalytics、ipapi、AbuseIPDB、IP2Location、ipdata、IPQS，字段映射参考原项目调用的 [xykt/IPQuality](https://github.com/xykt/IPQuality)。多数数据通过原脚本使用的 `ipinfo.check.place` 查询；ipapi 不可用时回退到[官方接口](https://ipapi.is/developers.html)。匿名备用接口只提供基础信息，缺失的安全字段显示为未知。

- 所有数据库请求明确携带目标 IP；不会把本机出口查询结果冒充为远端 IP 结果。
- 数据源可能限流、返回 403、暂时不可用或不支持某些 IPv6；这些情况明确显示“不可用/未知”，不会算成零分或低风险。
- 各家的评分单独显示，不混合为一个“总分”。ipapi 的公司网段滥用比例与单个 IP 的欺诈评分不同。
- DNS 黑名单检查 `zen.spamhaus.org` 与 `bl.spamcop.net`，通过 Google DNS over HTTPS 查询，仅支持 IPv4。检查阳性/阴性对照后才采用结果；解析器受限、异常返回码和失败均为“不可用”。不是原版的 400+ 列表扫描，也不表示 IP 在所有黑名单中都干净。
- **流媒体/AI 解锁、SMTP 连通性不会执行**，手动输入和本机模式统一如此。仅凭 IP 无法验证远端的实际访问能力。
- 不使用原来的 DB-IP `/self` 查询和 ipregistry 网页临时密钥，避免查询本机出口或依赖网页抓取。
- 内网、回环、链路本地、组播及其他非公网地址会显示“不适用”，不会发往外部数据库。输入应为 IP，不接受域名、CIDR 或接口后缀。

## 结果与网络请求

默认只显示在终端；只有 `-o` 才写本地文件。不上传整份报告，不生成在线报告链接，不进行截图上传、使用次数统计或广告请求。

数据库查询仍需联网，数据源会收到待查询 IP；默认 DNS 黑名单查询还会发送目标 IP 的反向形式给 Google DNS。本机模式额外使用 `api4.ipify.org` / `api6.ipify.org` 识别公网出口。所有程序内网络请求均为无请求体的 HTTPS GET。

JSON 顶层包含 `mode`、`upload_enabled: false`、`detection_errors` 和 `reports`；本机双栈会包含两份报告。每份报告含目标 IP、来源状态、信息、因子、评分、黑名单和跳过项目。第三方字符串在终端展示前移除控制字符。

退出码：`0` 至少一份报告有可用数据（可能只有部分来源）；`1` 所有来源失败、没有公网地址、非公网地址或文件保存失败；`2` 输入/参数错误；`130` 用户取消。

## 本地开发与验证

```bash
python3 scripts/build_launcher.py
python3 -m unittest discover -s tests -v
bash -n NodeQuality.sh
```

修改 `ip_quality.py` 后重新生成 `NodeQuality.sh`，两者一起提交。构建不需要额外依赖。测试使用模拟响应，覆盖指定 IP、回车检测本机、双栈/单栈、错误处理、本地保存、拒绝上传以及单文件打包。

本项目基于 [Loading886/NodeQuality](https://github.com/Loading886/NodeQuality) / [LloydAsp/NodeQuality](https://github.com/LloydAsp/NodeQuality)，沿用 [AGPL-3.0 许可证](LICENSE)。感谢 xykt/IPQuality 的数据库字段及检测逻辑参考。
