#requires -Version 7.0
# Native PowerShell IP quality queries; no Python, external programs or uploads.
# Provider mappings reference xykt/IPQuality v2026-09-16, AGPL-3.0.
[CmdletBinding()]
param(
    [Alias('i')][string]$TargetIP,
    [switch]$Local,
    [Alias('j')][switch]$Json,
    [Alias('o')][string]$OutputPath,
    [ValidateRange(1, 60)][int]$Timeout = 10,
    [switch]$NoDnsbl
)

function Get-NQValue($Data, [string]$Path) {
    foreach ($part in $Path.Split('.')) {
        if ($Data -isnot [System.Collections.IDictionary]) { return $null }
        $Data = $Data[$part]
    }
    if ($null -eq $Data -or ($Data -is [string] -and ($Data -ceq '' -or $Data -ceq 'null'))) { return $null }
    if ($Data -is [string] -or $Data -is [ValueType]) { return $Data }
    return $null
}

function ConvertTo-NQFlag($Value) {
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [string] -and $Value -in @('true', 'false')) { return $Value -eq 'true' }
    return $null
}

function Get-NQAnyFlag($Data, [string[]]$Paths) {
    $missing = $false
    foreach ($path in $Paths) {
        $value = ConvertTo-NQFlag (Get-NQValue $Data $path)
        if ($value -eq $true) { return $true }
        if ($null -eq $value) { $missing = $true }
    }
    if ($missing) { return $null }
    return $false
}

function ConvertTo-NQScore($Value) {
    if ($null -eq $Value -or $Value -is [bool]) { return $null }
    $number = 0.0
    if ([double]::TryParse([string]$Value, [Globalization.NumberStyles]::Float,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$number) -and
        [double]::IsFinite($number) -and $number -ge 0 -and $number -le 100) { return $number }
    return $null
}

function ConvertTo-NQIP([string]$Value) {
    $value = $Value.Trim()
    $address = $null
    if ($value.Contains(':')) {
        if ($value -notmatch '^[0-9a-fA-F:.]+$') { throw 'IP 地址格式无效。' }
        if ($value.Contains('.')) {
            $null = ConvertTo-NQIP $value.Substring($value.LastIndexOf(':') + 1)
        }
    } else {
        if ($value -notmatch '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$') {
            throw 'IP 地址格式无效。请输入 IPv4 或 IPv6，不接受域名、网段和接口后缀。'
        }
    }
    if (-not [Net.IPAddress]::TryParse($value, [ref]$address)) { throw 'IP 地址格式无效。' }
    if ($address.IsIPv4MappedToIPv6) { $address = $address.MapToIPv4() }
    return $address
}

function Test-NQSubnet([Net.IPAddress]$Address, [string]$Cidr) {
    $network, $prefix = $Cidr.Split('/')
    $left = $Address.GetAddressBytes()
    $right = [Net.IPAddress]::Parse($network).GetAddressBytes()
    if ($left.Length -ne $right.Length) { return $false }
    $remaining = [int]$prefix
    for ($index = 0; $remaining -gt 0; $index++) {
        $bits = [Math]::Min(8, $remaining)
        $mask = (255 -shl (8 - $bits)) -band 255
        if (($left[$index] -band $mask) -ne ($right[$index] -band $mask)) { return $false }
        $remaining -= $bits
    }
    return $true
}

function Test-NQPublic([Net.IPAddress]$Address) {
    if ($Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        if ($Address.ToString() -in @('192.0.0.9', '192.0.0.10')) { return $true }
        $excluded = @('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
            '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
            '192.168.0.0/16', '192.88.99.0/24', '198.18.0.0/15', '198.51.100.0/24',
            '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4')
    } else {
        if (-not (Test-NQSubnet $Address '2000::/3')) { return $false }
        $excluded = @('2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20')
    }
    foreach ($cidr in $excluded) { if (Test-NQSubnet $Address $cidr) { return $false } }
    return $true
}

function New-NQClient([int]$Seconds) {
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($Seconds)
    $client.MaxResponseContentBufferSize = 2MB
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('NodeQuality-IP/1.0')
    $client.DefaultRequestHeaders.Accept.ParseAdd('application/json')
    return $client
}

function Get-NQJson([string]$Url) {
    $response = $null
    try {
        # The only HTTP operation in the query engine: GET, with no request body.
        $response = $script:NQClient.GetAsync($Url).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) { throw "HTTP $([int]$response.StatusCode)" }
        $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $data = ConvertFrom-Json -InputObject $content -AsHashtable -ErrorAction Stop
        if ($data -isnot [System.Collections.IDictionary] -or $data.Count -eq 0) {
            throw 'empty or invalid JSON'
        }
        if ($data['error'] -or $data['errors'] -or $data['success'] -eq $false) {
            throw 'provider rejected the query'
        }
        return $data
    } catch {
        if ($_.Exception.Message -match '^HTTP [0-9]{3}$') { throw $_.Exception.Message }
        throw '请求失败、超时或数据无效'
    } finally {
        if ($null -ne $response) { $response.Dispose() }
    }
}

function Get-NQLocalIPs {
    $addresses = [Collections.Generic.List[Net.IPAddress]]::new()
    $errors = [Collections.Generic.List[string]]::new()
    foreach ($version in @(4, 6)) {
        try {
            $data = Get-NQJson "https://api$version.ipify.org?format=json"
            $address = ConvertTo-NQIP $data['ip']
            $actualVersion = if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 4 } else { 6 }
            if ($actualVersion -ne $version -or -not (Test-NQPublic $address)) { throw 'unexpected address' }
            $addresses.Add($address)
        } catch { $errors.Add("IPv${version}: $($_.Exception.Message)") }
    }
    if ($addresses.Count -eq 0) { throw "无法识别本机公网 IP，请手动输入。$($errors -join '; ')" }
    return @{ addresses = $addresses.ToArray(); errors = $errors.ToArray() }
}

function ConvertFrom-NQProvider([string]$Name, $Data) {
    $info = [ordered]@{}; $factors = [ordered]@{}; $scores = [ordered]@{}
    $infoPaths = @{}; $factorPaths = @{}
    switch ($Name) {
        'MaxMind' {
            $infoPaths = [ordered]@{ country = 'City.Country.Name'; city = 'City.Name'; asn = 'ASN.AutonomousSystemNumber'; organization = 'ASN.AutonomousSystemOrganization'; timezone = 'City.Location.TimeZone' }
        }
        'IPinfo' {
            $infoPaths = [ordered]@{ country = 'data.country'; region = 'data.region'; city = 'data.city'; asn = 'data.asn.asn'; organization = 'data.asn.name'; usage_type = 'data.asn.type'; company_type = 'data.company.type'; timezone = 'data.timezone' }
            $factorPaths = @{ proxy = 'data.privacy.proxy'; vpn = 'data.privacy.vpn'; tor = 'data.privacy.tor'; hosting = 'data.privacy.hosting' }
        }
        'Scamalytics' {
            $infoPaths = @{ country = 'external_datasources.maxmind_geolite2.ip_country_code' }
            $factorPaths = @{ proxy = 'external_datasources.firehol.is_proxy'; vpn = 'scamalytics.scamalytics_proxy.is_vpn'; tor = 'external_datasources.x4bnet.is_tor'; hosting = 'scamalytics.scamalytics_proxy.is_datacenter'; abuser = 'scamalytics.is_blacklisted_external' }
            $factors['bot'] = Get-NQAnyFlag $Data @('external_datasources.x4bnet.is_blacklisted_spambot', 'external_datasources.x4bnet.is_bot_operamini', 'external_datasources.x4bnet.is_bot_semrush')
            $scores['fraud_score_0_100'] = ConvertTo-NQScore (Get-NQValue $Data 'scamalytics.scamalytics_score')
        }
        'ipapi' {
            $infoPaths = [ordered]@{ country = 'location.country'; region = 'location.state'; city = 'location.city'; asn = 'asn.asn'; organization = 'asn.org'; usage_type = 'asn.type'; company_type = 'company.type'; timezone = 'location.timezone' }
            $factorPaths = @{ proxy = 'is_proxy'; vpn = 'is_vpn'; tor = 'is_tor'; hosting = 'is_datacenter'; abuser = 'is_abuser'; bot = 'is_crawler' }
            $value = Get-NQValue $Data 'company.abuser_score'
            if ($value -is [string] -and $value -match '^([01](?:\.\d+)?)(?: \([^\r\n]*\))?$') {
                $ratio = [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture)
                if ($ratio -le 1) { $scores['company_abuse_ratio'] = $value }
            }
            if ($Data['asn'] -is [string]) {
                $infoPaths = [ordered]@{ country = 'country'; region = 'region'; city = 'city'; asn = 'asn'; organization = 'company'; timezone = 'timezone' }
            }
        }
        'AbuseIPDB' {
            $infoPaths = @{ country = 'data.countryCode'; usage_type = 'data.usageType'; organization = 'data.isp' }
            $factorPaths = @{ tor = 'data.isTor' }
            $scores['abuse_confidence_0_100'] = ConvertTo-NQScore (Get-NQValue $Data 'data.abuseConfidenceScore')
        }
        'IP2Location' {
            $infoPaths = @{ country = 'country_code'; usage_type = 'usage_type'; company_type = 'as_info.as_usage_type' }
            $factorPaths = @{ vpn = 'proxy.is_vpn'; tor = 'proxy.is_tor'; hosting = 'proxy.is_data_center'; abuser = 'proxy.is_spammer' }
            $factors['proxy'] = Get-NQAnyFlag $Data @('is_proxy', 'proxy.is_public_proxy', 'proxy.is_web_proxy')
            $factors['bot'] = Get-NQAnyFlag $Data @('proxy.is_web_crawler', 'proxy.is_scanner', 'proxy.is_botnet')
            $scores['fraud_score_0_100'] = ConvertTo-NQScore (Get-NQValue $Data 'fraud_score')
        }
        'ipdata' {
            $infoPaths = @{ country = 'country_code' }
            $factorPaths = @{ proxy = 'threat.is_proxy'; tor = 'threat.is_tor'; hosting = 'threat.is_datacenter' }
            $factors['abuser'] = Get-NQAnyFlag $Data @('threat.is_threat', 'threat.is_known_abuser', 'threat.is_known_attacker')
        }
        'IPQS' {
            $infoPaths = @{ country = 'country_code' }
            $factorPaths = @{ proxy = 'proxy'; vpn = 'vpn'; tor = 'tor'; abuser = 'recent_abuse'; bot = 'bot_status' }
            $scores['fraud_score_0_100'] = ConvertTo-NQScore (Get-NQValue $Data 'fraud_score')
        }
    }
    foreach ($key in $infoPaths.Keys) { $info[$key] = Get-NQValue $Data $infoPaths[$key] }
    foreach ($key in $factorPaths.Keys) { $factors[$key] = ConvertTo-NQFlag (Get-NQValue $Data $factorPaths[$key]) }
    return @{ info = $info; factors = $factors; scores = $scores }
}

function Get-NQProvider([string]$Name, [string]$IP) {
    $databases = @{ Scamalytics = 'scamalytics'; ipapi = 'ipapi'; AbuseIPDB = 'abuseipdb'; IP2Location = 'ip2location'; ipdata = 'ipdata'; IPQS = 'ipqualityscore' }
    $urls = switch ($Name) {
        'IPinfo' { "https://ipinfo.io/widget/demo/$IP" }
        'MaxMind' { "https://ipinfo.check.place/${IP}?lang=cn" }
        default { "https://ipinfo.check.place/${IP}?db=$($databases[$Name])" }
    }
    if ($Name -eq 'ipapi') { $urls = @($urls) + "https://api.ipapi.is/?q=$([Uri]::EscapeDataString($IP))" }
    $errors = [Collections.Generic.List[string]]::new()
    foreach ($url in $urls) {
        try {
            $data = Get-NQJson $url
            $identityPaths = if ($Name -eq 'IPinfo') { @('data.ip') } else { @('data.ipAddress', 'ip', 'ipAddress') }
            foreach ($path in $identityPaths) {
                $returnedIP = Get-NQValue $data $path
                if ($null -ne $returnedIP -and (ConvertTo-NQIP ([string]$returnedIP)).ToString() -ne $IP) {
                    throw '返回的 IP 与查询目标不一致'
                }
            }
            $result = ConvertFrom-NQProvider $Name $data
            $recognized = $false
            foreach ($section in @('info', 'factors', 'scores')) {
                foreach ($value in $result[$section].Values) { if ($null -ne $value) { $recognized = $true } }
            }
            if (-not $recognized) { throw '未返回可识别的目标 IP 数据' }
            $result['name'] = $Name; $result['status'] = 'ok'; $result['source'] = $url
            if ($errors.Count -gt 0) { $result['fallback_reason'] = $errors -join '; ' }
            return $result
        } catch { $errors.Add($_.Exception.Message) }
    }
    return @{ name = $Name; status = 'unavailable'; error = $errors -join '; '; info = @{}; factors = @{}; scores = @{} }
}

function Get-NQDnsAnswer([string]$Name, [string[]]$Codes) {
    $data = Get-NQJson "https://dns.google/resolve?name=$([Uri]::EscapeDataString($Name))&type=A&edns_client_subnet=0.0.0.0%2F0"
    if ($data['TC'] -or $data['Status'] -notin @(0, 3)) { throw 'DNS 查询失败' }
    $answers = $data['Answer']
    if ($null -ne $answers -and $answers -isnot [array]) { throw 'DNS 应答无效' }
    if ($data['Status'] -eq 3 -and $answers.Count -gt 0) { throw 'DNS 应答冲突' }
    $listed = $false
    foreach ($answer in $answers) {
        if ($answer -isnot [System.Collections.IDictionary]) { throw 'DNS 应答无效' }
        if ($answer['type'] -eq 1) {
            if ($answer['data'] -notin $Codes) { throw 'DNSBL 拒绝解析器或返回未知代码' }
            $listed = $true
        }
    }
    return $listed
}

function Get-NQDnsbl([string]$Zone, [string]$IP) {
    try {
        $codes = if ($Zone -eq 'zen.spamhaus.org') { @(2, 3, 4, 9, 10, 11 | ForEach-Object { "127.0.0.$_" }) } else { @('127.0.0.2') }
        if (-not (Get-NQDnsAnswer "2.0.0.127.$Zone" $codes)) { throw 'DNSBL 阳性对照失败，解析器可能受限' }
        if (Get-NQDnsAnswer "1.0.0.127.$Zone" $codes) { throw 'DNSBL 阴性对照失败' }
        $octets = $IP.Split('.'); [Array]::Reverse($octets)
        $state = if (Get-NQDnsAnswer "$(($octets -join '.')).$Zone" $codes) { 'listed' } else { 'not_listed' }
        return @{ name = $Zone; status = $state }
    } catch { return @{ name = $Zone; status = 'unavailable'; error = $_.Exception.Message } }
}

function Get-NQReport([Net.IPAddress]$Address, [bool]$Dnsbl = $true) {
    $version = if ($Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 4 } else { 6 }
    $report = [ordered]@{ target_ip = $Address.ToString(); ip_version = $version; generated_at = [DateTimeOffset]::UtcNow.ToString('o'); upload_enabled = $false; providers = @(); dnsbl = @(); skipped = @{ media_unlock = 'requires_target_egress'; smtp_connectivity = 'requires_target_egress'; 'DB-IP' = 'upstream_endpoint_uses_requester_ip' } }
    if (-not (Test-NQPublic $Address)) {
        $report['status'] = 'not_applicable'; $report['reason'] = 'non_public_ip'
        return $report
    }
    $report['providers'] = @(foreach ($name in @('MaxMind', 'IPinfo', 'Scamalytics', 'ipapi', 'AbuseIPDB', 'IP2Location', 'ipdata', 'IPQS')) {
        [Console]::Error.WriteLine("正在查询 $($Address.ToString()) / $name…")
        Get-NQProvider $name $Address.ToString()
    })
    if ($Dnsbl -and $version -eq 4) {
        $report['dnsbl'] = @(foreach ($zone in @('zen.spamhaus.org', 'bl.spamcop.net')) { Get-NQDnsbl $zone $Address.ToString() })
    } else { $report['skipped']['dnsbl'] = if ($Dnsbl) { 'ipv4_only' } else { 'disabled' } }
    $available = @($report['providers'] | Where-Object { $_.status -eq 'ok' }).Count
    $report['status'] = if ($available -eq 8) { 'ok' } elseif ($available -gt 0) { 'partial' } else { 'unavailable' }
    return $report
}

function Format-NQValue($Value) {
    if ($null -eq $Value) { return '未知' }
    if ($Value -is [bool]) { return $(if ($Value) { '是' } else { '否' }) }
    $text = [regex]::Replace([string]$Value, '[\p{Cc}\p{Cf}]', '')
    return $text.Substring(0, [Math]::Min(250, $text.Length))
}

function Format-NQReport($Report) {
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('=' * 72); $lines.Add('NodeQuality — IP 质量查询（PowerShell 原生版）')
    $lines.Add("IP: $($Report.target_ip) (IPv$($Report.ip_version))")
    $lines.Add("UTC: $($Report.generated_at)"); $lines.Add('报告仅保留在本地，不上传结果。')
    if ($Report.status -eq 'not_applicable') {
        $lines.Add('非公网地址，公网信誉查询不适用；未发送外部请求。')
        return ($lines -join "`n") + "`n"
    }
    $infoLabels = @{ country = '国家/地区'; region = '省/州'; city = '城市'; asn = 'ASN'; organization = '机构'; usage_type = '使用类型'; company_type = '公司类型'; timezone = '时区' }
    $scoreLabels = @{ fraud_score_0_100 = '欺诈评分 0–100'; abuse_confidence_0_100 = '滥用置信度 0–100'; company_abuse_ratio = '公司网段滥用比例' }
    foreach ($provider in $Report.providers) {
        $lines.Add(''); $lines.Add("[$($provider.name)]")
        if ($provider.status -ne 'ok') { $lines.Add("  不可用：$(Format-NQValue $provider.error)"); continue }
        if ($provider.fallback_reason) { $lines.Add('  使用备用接口；缺失的安全字段为未知。') }
        foreach ($key in $provider.info.Keys) {
            if ($null -ne $provider.info[$key]) { $lines.Add("  $($infoLabels[$key]): $(Format-NQValue $provider.info[$key])") }
        }
        foreach ($key in $provider.scores.Keys) { $lines.Add("  $($scoreLabels[$key]): $(Format-NQValue $provider.scores[$key])") }
        if ($provider.name -ne 'MaxMind') {
            $values = foreach ($key in @('proxy', 'vpn', 'tor', 'hosting', 'abuser', 'bot')) { Format-NQValue $provider.factors[$key] }
            $lines.Add("  代理 / VPN / Tor / 机房 / 滥用 / 机器人：$($values -join ' / ')")
        }
    }
    $lines.Add(''); $lines.Add('DNS 黑名单：')
    $states = @{ listed = '列入'; not_listed = '未列入'; unavailable = '不可用' }
    foreach ($item in $Report.dnsbl) {
        $detail = if ($item.error) { " ($(Format-NQValue $item.error))" } else { '' }
        $lines.Add("  $($item.name): $($states[$item.status])$detail")
    }
    if ($Report.dnsbl.Count -eq 0) { $lines.Add('  已跳过（用户禁用或目标为 IPv6）。') }
    $lines.Add(''); $lines.Add('流媒体/SMTP 连通性未执行；必须从目标 IP 发起连接才能判断。')
    $lines.Add('缺失数据表示未知，不代表低风险。DNS 黑名单仅覆盖上面列出的两个库。')
    $lines.Add('查询会将目标 IP 发送给数据源；生成的整份报告不会发送。')
    $lines.Add('=' * 72)
    return ($lines -join "`n") + "`n"
}

function Invoke-NQMain {
    param([string]$TargetIP, [switch]$Local, [switch]$Json, [string]$OutputPath,
          [ValidateRange(1, 60)][int]$Timeout = 10, [switch]$NoDnsbl)
    $global:LASTEXITCODE = 1
    if ($Local -and $TargetIP) { throw '请只指定一个 IP 或 -Local。' }
    if ($OutputPath -and (Test-Path -LiteralPath $OutputPath)) { throw '输出文件已存在，请换一个路径。' }
    $address = $null
    if (-not $Local -and -not $TargetIP) {
        while ($true) {
            [Console]::Error.Write('输入你要检测的 IP，直接回车检测本机 IP：')
            $inputValue = [Console]::ReadLine()
            if ($null -eq $inputValue) { throw '未读取到输入，请用 -Local 或 -i IP。' }
            $TargetIP = $inputValue.Trim()
            if (-not $TargetIP) { break }
            try { $address = ConvertTo-NQIP $TargetIP; break }
            catch { [Console]::Error.WriteLine($_.Exception.Message) }
        }
    } elseif ($TargetIP) { $address = ConvertTo-NQIP $TargetIP }
    $script:NQClient = New-NQClient $Timeout
    try {
        $detectionErrors = @()
        if ($null -eq $address) {
            $detected = Get-NQLocalIPs; $addresses = $detected.addresses; $detectionErrors = $detected.errors
        } else { $addresses = @($address) }
        foreach ($message in $detectionErrors) { [Console]::Error.WriteLine($message) }
        $reports = @(foreach ($item in $addresses) { Get-NQReport $item (-not $NoDnsbl) })
        $mode = if ($TargetIP) { 'specified_ip' } else { 'local_public_ip' }
        $bundle = [ordered]@{ mode = $mode; upload_enabled = $false; detection_errors = @($detectionErrors); reports = @($reports) }
        $jsonText = ConvertTo-Json -InputObject $bundle -Depth 15
        $reportText = ($reports | ForEach-Object { Format-NQReport $_ }) -join "`n"
        if ($Json) { Write-Output $jsonText } else { Write-Output $reportText }
        if ($OutputPath) {
            $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
            $contents = if ([IO.Path]::GetExtension($fullPath) -eq '.json') { $jsonText } else { $reportText }
            $stream = [IO.File]::Open($fullPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
            try {
                $bytes = [Text.UTF8Encoding]::new($false).GetBytes($contents + "`n")
                $stream.Write($bytes, 0, $bytes.Length)
            } finally { $stream.Dispose() }
            [Console]::Error.WriteLine("已保存到本地：$fullPath")
        }
        if (@($reports | Where-Object { $_.status -in @('ok', 'partial') }).Count -gt 0) { $global:LASTEXITCODE = 0 }
    } finally { $script:NQClient.Dispose() }
}

# Dot sourcing exposes functions for tests; normal invocation runs the prompt.
if ($MyInvocation.InvocationName -ne '.') { Invoke-NQMain @PSBoundParameters }
