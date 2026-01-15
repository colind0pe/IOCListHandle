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


if ($typeDict["IP"].Count -gt 0) {
    $ipList = $typeDict["IP"] | ForEach-Object { "`"$_`"" }
    $ipQuery = $ipList -join " or "
    Write-Output "IP Search Query - Firewall Log (Index: filebeat-*):"
    Write-Output "source.ip: ($ipQuery) or destination.ip: ($ipQuery)"
}

if ($typeDict["Domain"].Count -gt 0) {
    $domainList = $typeDict["Domain"] | ForEach-Object { "`"$_`"" }
    $domainQuery = $domainList -join " or "
    Write-Output "`nDomain Search Query - Proxy Log (Index: filebeat-*):"
    Write-Output "observer.product: `"Web Security`" and destination.domain: ($domainQuery)"
    Write-Output "`nDomain Search Query - DNS Log (Index: filebeat-* and packetbeat-*): "
    Write-Output "`dns.question.name: ($domainQuery)"
    Write-Output "`nDomain Search Query - Firewall Log (Index: filebeat-*): "
    Write-Output "((tags: paloalto and Firewall.type: THREAT and Threat.name: URL-filtering) or (tagscls: fortinet and fortinet.firewall.type: utm and fortinet.firewall.subtype: (app-ctrl or webfilter))) and url.domain: ($domainQuery)"
}
