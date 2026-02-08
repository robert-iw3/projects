<#
Get-TargetDomainInfo.ps1
Run on any domain-joined machine (preferably the new DC) in the TARGET domain
Outputs everything needed for the migration script + saves JSON for auto-load
#>

Import-Module ActiveDirectory -ErrorAction SilentlyContinue
if (-not (Get-Module -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Run on a domain-joined machine with RSAT or on a DC."
    exit 1
}

try {
    $domain   = Get-ADDomain
    $dcInfo   = Get-ADDomainController

    $info = [PSCustomObject]@{
        DomainFQDN          = $domain.DNSRoot
        NetBIOSName         = $domain.NetBIOSName
        DCPrefix            = $dcInfo.HostName.Split('.')[0].ToLower()
        DCFQDN              = $dcInfo.HostName.ToLower()
        SIDBase             = ($domain.DomainSID.Value -split '-' | Select-Object -Last 3) -join '-'
        DomainAdminsSID     = "$($domain.DomainSID.Value)-512"
        EnterpriseAdminsSID = "$($domain.DomainSID.Value)-519"
    }

    Write-Host "`n=== TARGET (NEW) DOMAIN INFORMATION ===`n" -ForegroundColor Cyan
    $info | Format-List

    $jsonPath = "TargetDomainInfo_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $info | ConvertTo-Json | Out-File $jsonPath -Encoding utf8
    Write-Host "`nSaved as JSON → $jsonPath" -ForegroundColor Green
    Write-Host "`nCopy this JSON file to your GPO backup folder and run Migrate-GPOBackups.ps1`n" -ForegroundColor Yellow
}
catch {
    Write-Error "Failed to retrieve domain info: $($_.Exception.Message)"
}