param(
    [Parameter(Mandatory = $false)]
    [string]$csvPath
)

if (-not $csvPath) {
    Write-Host "Usage: .\IOCListHandle.ps1 -csvPath <csv_file_path>"
    exit 1
}

$data = Import-Csv -Path $csvPath


$typeDict = @{
    "Domain" = @()
    "IP"     = @()
    "URL"    = @()
}

foreach ($row in $data) {
    $type = $row.'IOC Type'
    $value = $row.'IOC Value'
    if ($typeDict.ContainsKey($type) -and $value) {
        $cleanValue = $value -replace '\[|\]', ''
        $typeDict[$type] += $cleanValue
    }
}

foreach ($url in $typeDict["URL"]) {
    if ($url) {
        try {
            $uri = [Uri]::new($url)
            $domain = $uri.Host
        } catch {
            if ($url -match '^(?:https?://)?([^/]+)') {
                $domain = $matches[1]
            } else {
                $domain = $null
            }
        }
        if ($domain -and -not ($typeDict["Domain"] -contains $domain)) {
            $typeDict["Domain"] += $domain
        }
    }
}

$ipList = $typeDict["IP"] | Where-Object { $_ } | ForEach-Object { "`"$_`"" }
$domainList = $typeDict["Domain"] | Where-Object { $_ } | ForEach-Object { "`"$_`"" }

$ipQuery = $ipList -join " or "
$domainQuery = $domainList -join " or "

if ($ipList.Count -gt 0 -or $domainList.Count -gt 0) {
    Write-Output "Firewall Log Search (Index: filebeat-*):"
    $firewallParts = @()
    if ($ipList.Count -gt 0) {
        $firewallParts += "(source.ip: ($ipQuery) or destination.ip: ($ipQuery))"
    }
    if ($domainList.Count -gt 0) {
        $firewallParts += "((tags: paloalto and Firewall.type: THREAT and Threat.name: URL-filtering) or (tagscls: fortinet and fortinet.firewall.type: utm and fortinet.firewall.subtype: (app-ctrl or webfilter))) and url.domain: ($domainQuery)"
    }
    if ($firewallParts.Count -gt 0) {
        Write-Output ($firewallParts -join " or ")
    }
    Write-Output ""
}

if ($domainList.Count -gt 0) {
    Write-Output "Proxy Log Search (Index: filebeat-*):"
    Write-Output "observer.product: `"Web Security`" and destination.domain: ($domainQuery)"
    Write-Output ""
}

if ($domainList.Count -gt 0) {
    Write-Output "DNS Log Search (Index: filebeat-* and packetbeat-*):"
    Write-Output "dns.question.name: ($domainQuery)"
    Write-Output ""
}
