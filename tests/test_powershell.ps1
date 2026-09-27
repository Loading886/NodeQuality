# Native tests; no Python, Pester or external modules required.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../NodeQuality.ps1')
$script:assertions = 0
function Assert-NQ([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:assertions++
}
function Assert-NQThrows([scriptblock]$Code) {
    $failed = $false
    try { & $Code | Out-Null } catch { $failed = $true }
    Assert-NQ $failed 'Expected a failure'
}
foreach ($ip in @('1.1.1.1', '2606:4700:4700::1111', '::ffff:1.1.1.1')) {
    Assert-NQ ((ConvertTo-NQIP $ip) -is [Net.IPAddress]) 'Valid address rejected'
}
foreach ($invalid in @('1', '01.2.3.4', '1.2.3.999', 'host.example', '1.2.3.4/24',
        '1.2.3.4;echo bad', 'fe80::1%eth0', '::ffff:01.2.3.4', '2001:::1')) {
    Assert-NQThrows { ConvertTo-NQIP $invalid }
}
Assert-NQ ($null -eq (ConvertTo-NQScore $null)) 'Missing score became zero'
Assert-NQ ((ConvertTo-NQScore 0) -ceq 0.0) 'Valid zero score lost'
Assert-NQ ($null -eq (ConvertTo-NQScore 'nan')) 'Non-finite score accepted'
Assert-NQ ((Get-NQValue @{flag = $false} 'flag') -ceq $false) 'False flag lost'
Assert-NQ ((Get-NQValue @{score = 0} 'score') -ceq 0) 'Zero score lost'
Assert-NQ ($null -eq (Get-NQAnyFlag @{a = $false} @('a', 'b'))) 'Partial flags became false'
Assert-NQ ((Get-NQAnyFlag @{a = $false; b = $false} @('a', 'b')) -ceq $false) 'False flags changed'
$mappingCases = @(
    @('MaxMind', @{ASN = @{AutonomousSystemNumber = 13335}}, 'info', 'asn', 13335),
    @('IPinfo', @{data = @{privacy = @{hosting = $true}}}, 'factors', 'hosting', $true),
    @('Scamalytics', @{scamalytics = @{scamalytics_score = 42}}, 'scores', 'fraud_score_0_100', 42),
    @('ipapi', @{company = @{abuser_score = '0.1 (High)'}}, 'scores', 'company_abuse_ratio', '0.1 (High)'),
    @('AbuseIPDB', @{data = @{abuseConfidenceScore = 0}}, 'scores', 'abuse_confidence_0_100', 0),
    @('IP2Location', @{proxy = @{is_vpn = $true}}, 'factors', 'vpn', $true),
    @('ipdata', @{threat = @{is_known_attacker = $true}}, 'factors', 'abuser', $true),
    @('IPQS', @{bot_status = $false}, 'factors', 'bot', $false)
)
foreach ($case in $mappingCases) {
    $result = ConvertFrom-NQProvider $case[0] $case[1]
    Assert-NQ ($result[$case[2]][$case[3]] -ceq $case[4]) "Provider mapping failed: $($case[0])"
    $empty = ConvertFrom-NQProvider $case[0] @{}
    foreach ($section in $empty.Values) {
        foreach ($value in $section.Values) { Assert-NQ ($null -eq $value) 'Missing value fabricated' }
    }
}
$originalFetch = (Get-Item Function:Get-NQJson).ScriptBlock
function Get-NQJson([string]$Url) { throw 'No requests expected' }
foreach ($ip in @('127.0.0.1', '192.168.1.1', '::1', 'fe80::1', '224.0.0.1', 'ff02::1', '100.64.0.1')) {
    Assert-NQ ((Get-NQReport (ConvertTo-NQIP $ip)).status -eq 'not_applicable') 'Private target queried'
}
function Get-NQJson([string]$Url) { return @{data = @{ip = '8.8.8.8'; country = 'US'}} }
Assert-NQ ((Get-NQProvider 'IPinfo' '1.1.1.1').status -eq 'unavailable') 'Wrong target accepted'
function Get-NQJson([string]$Url) {
    if ($Url.Contains('check.place')) { throw 'HTTP 403' }
    return @{ip = '1.1.1.1'; asn = 'AS13335'; company = 'Cloudflare'}
}
$fallback = Get-NQProvider 'ipapi' '1.1.1.1'
Assert-NQ ($fallback.status -eq 'ok' -and $fallback.fallback_reason) 'Fallback failed'
Assert-NQ ($null -eq $fallback.factors.vpn) 'Fallback invented security data'
$script:urls = [Collections.Generic.List[string]]::new()
function Get-NQJson([string]$Url) {
    $script:urls.Add($Url)
    return @{data = @{ip = '2606:4700:4700::1111'; country = 'US'}}
}
$v6 = Get-NQReport (ConvertTo-NQIP '2606:4700:4700::1111')
Assert-NQ ($v6.ip_version -eq 6 -and $v6.skipped.dnsbl -eq 'ipv4_only') 'IPv6 handling failed'
foreach ($url in $script:urls) {
    Assert-NQ ([Uri]::UnescapeDataString($url).Contains('2606:4700:4700::1111')) 'Target omitted from query'
}
function Get-NQJson([string]$Url) { return @{Status = 0; Answer = @(@{type = 1; data = '127.255.255.254'})} }
Assert-NQ ((Get-NQDnsbl 'zen.spamhaus.org' '1.1.1.1').status -eq 'unavailable') 'DNS error became listed'
function Get-NQJson([string]$Url) { return @{Status = 3} }
Assert-NQ ((Get-NQDnsbl 'zen.spamhaus.org' '1.1.1.1').status -eq 'unavailable') 'Failed control became clean'
function Get-NQJson([string]$Url) {
    if ($Url.Contains('name=1.0.0.127.')) { return @{Status = 3} }
    return @{Status = 0; Answer = @(@{type = 1; data = '127.0.0.2'})}
}
Assert-NQ ((Get-NQDnsbl 'bl.spamcop.net' '1.2.3.4').status -eq 'listed') 'DNS listing missed'
function Get-NQJson([string]$Url) {
    if ($Url.Contains('api4.ipify.org')) { return @{ip = '8.8.8.8'} }
    if ($Url.Contains('api6.ipify.org')) { throw 'IPv6 unavailable' }
    return @{data = @{ip = '8.8.8.8'; country = 'US'}}
}
$singleStack = Get-NQLocalIPs
Assert-NQ ($singleStack.addresses.Count -eq 1 -and $singleStack.errors.Count -eq 1) 'Single stack detection failed'
$oldInput = [Console]::In
try {
    [Console]::SetIn([IO.StringReader]::new("`n"))
    $bundle = Invoke-NQMain -Json -NoDnsbl | ConvertFrom-Json -AsHashtable
    Assert-NQ ($bundle.mode -eq 'local_public_ip') 'Enter did not select local mode'
    Assert-NQ ($bundle.reports[0].target_ip -eq '8.8.8.8') 'Wrong local address'
    [Console]::SetIn([IO.StringReader]::new(''))
    Assert-NQThrows { Invoke-NQMain -Json }
    [Console]::SetIn([IO.StringReader]::new("bad`n127.0.0.1`n"))
    $bundle = Invoke-NQMain -Json | ConvertFrom-Json -AsHashtable
    Assert-NQ ($bundle.reports[0].target_ip -eq '127.0.0.1') 'Input retry failed'
} finally { [Console]::SetIn($oldInput) }
$temporary = Join-Path ([IO.Path]::GetTempPath()) "nodequality-$([Guid]::NewGuid()).json"
try {
    Invoke-NQMain -TargetIP '127.0.0.1' -Json -OutputPath $temporary | Out-Null
    $saved = Get-Content -LiteralPath $temporary -Raw | ConvertFrom-Json -AsHashtable
    Assert-NQ (-not $saved.upload_enabled) 'Report upload enabled'
    Assert-NQThrows { Invoke-NQMain -TargetIP '1.1.1.1' -OutputPath $temporary }
} finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary } }
Set-Item Function:Get-NQJson $originalFetch
# Check the production network boundary: one GET method, no external programs.
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../NodeQuality.ps1') -Raw
Assert-NQ ($source -match '\.GetAsync\(') 'GET boundary missing'
Assert-NQ ($source -notmatch '(?i)\.PostAsync\(|\.SendAsync\(|Start-Process|Invoke-Expression|python\s+-') 'Unexpected execution or upload path'
$global:LASTEXITCODE = 0
Write-Output "PowerShell tests: $script:assertions assertions passed."
