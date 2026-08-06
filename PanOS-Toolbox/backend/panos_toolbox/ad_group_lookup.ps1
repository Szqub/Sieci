$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)

function Write-Result {
    param([Parameter(Mandatory = $true)]$Value)
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    [Console]::Out.Write(($Value | ConvertTo-Json -Depth 6 -Compress))
}

try {
    $raw = [Console]::In.ReadToEnd()
    $payload = $raw | ConvertFrom-Json -ErrorAction Stop
    $names = @($payload.groups)
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Result ([ordered]@{
        ok = $false
        code = "AD_MODULE_UNAVAILABLE"
        message = "Nie można załadować modułu ActiveDirectory. Zainstaluj RSAT lub uruchom Toolbox na stacji z modułem AD."
    })
    exit 0
}

$results = foreach ($nameValue in $names) {
    $name = [string]$nameValue
    try {
        $group = Get-ADGroup -Identity $name -Properties Members -ErrorAction Stop
        $memberCount = @($group.Members).Count
        [ordered]@{
            name = $name
            status = $(if ($memberCount -gt 0) { "valid" } else { "empty" })
            memberCount = $memberCount
            distinguishedName = [string]$group.DistinguishedName
        }
    }
    catch {
        $notFound = $_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound
        [ordered]@{
            name = $name
            status = $(if ($notFound) { "not-found" } else { "error" })
            memberCount = 0
            distinguishedName = $null
        }
    }
}

Write-Result ([ordered]@{ ok = $true; groups = @($results) })
