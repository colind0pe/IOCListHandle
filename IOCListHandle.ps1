
param(
    [Parameter(Mandatory = $false)]
    [string]$csvPath
)

if (-not $csvPath) {
    Write-Host "Usage: .\IOCListHandle.ps1 -csvPath <csv_file_path>"
    exit 1
}

$typeDict = @{ Domain = @(); IP = @(); URL = @() }
Import-Csv -Path $csvPath | ForEach-Object {
    $type = $_.'IOC Type'
    $value = $_.'IOC Value' -replace '\[|\]', ''
    if ($typeDict.ContainsKey($type) -and $value) {
        $typeDict[$type] += $value
    }
}

$typeDict.URL | Where-Object { $_ } | ForEach-Object {
    try {
        $domain = ([Uri]$_).Host
    } catch {
        if ($_ -match '^(?:https?://)?([^/]+)') { $domain = $matches[1] } else { $domain = $null }
    }
    if ($domain -and -not ($typeDict.Domain -contains $domain)) {
        $typeDict.Domain += $domain
    }
}


$whitelistPath = Join-Path -Path $PSScriptRoot -ChildPath 'DomainWhitelist.txt'
$whitelist = @()
if (Test-Path $whitelistPath) {
    $whitelist = Get-Content $whitelistPath | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object { $_.Trim() }
}

$filteredDomains = $typeDict.Domain | Where-Object { $_ -and ($whitelist -notcontains $_) }
$ipList = $typeDict.IP | Where-Object { $_ } | ForEach-Object { '"' + $_ + '"' }
$domainList = $filteredDomains | ForEach-Object { '"*' + $_ + '*"' }
$ipQuery = $ipList -join ' or '
$domainQuery = $domainList -join ' or '

if ($domainList) {
    Write-Output "Proxy Log Search (Index: filebeat-*):"
    Write-Output "observer.product: `"Web Security`" and destination.domain: ($domainQuery)"
    Write-Output ""
}

if ($ipList -or $domainList) {
    Write-Output "Firewall Log Search (Index: filebeat-*):"
    $firewallParts = @()
    if ($ipList) {
        $firewallParts += "(source.ip: ($ipQuery) or destination.ip: ($ipQuery))"
    }
    if ($domainList) {
        $firewallParts += "((tags: paloalto and Firewall.type: THREAT and Threat.name: URL-filtering) or (tagscls: fortinet and fortinet.firewall.type: utm and fortinet.firewall.subtype: (app-ctrl or webfilter))) and url.domain: ($domainQuery)"
    }
    if ($firewallParts) {
        Write-Output ($firewallParts -join " or ")
    }
    Write-Output ""
}

if ($domainList) {
    Write-Output "DNS Log Search (Index: filebeat-* and packetbeat-*):"
    Write-Output "dns.question.name: ($domainQuery)"
    Write-Output ""
}
