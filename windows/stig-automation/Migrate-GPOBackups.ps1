<#
Migrate-GPOBackups.ps1
Replaces domain, NetBiosName, Placeholder, domain, DC, SYSVOL paths, SIDs, and migration table placeholders.
Works with real GPO backups and STIG packages.
Run in the folder that contains your GPO backups or the "domain-controller-stig" folder.
#>

$rootPath = Get-Location

# Old values
$oldDomain   = Read-Host "Old domain FQDN (e.g. domain.local)"
if (!$oldDomain)   { $oldDomain = "domain.local" }

$oldDcPrefix = Read-Host "Old DC prefix (e.g. dc-prim or dc)"
if (!$oldDcPrefix) { $oldDcPrefix = "dc-prim" }

$oldDcFqdn   = "$oldDcPrefix.$oldDomain"

# New values (auto-load from JSON if present)
$newDomain = $newDcPrefix = $newNetbios = $newSidBase = $null

$jsonFile = Get-ChildItem -Path $rootPath -Filter "TargetDomainInfo_*.json" -Recurse | Sort LastWriteTime -Descending | Select -First 1
if ($jsonFile) {
    $target = Get-Content $jsonFile.FullName | ConvertFrom-Json
    $newDomain   = $target.DomainFQDN
    $newDcPrefix = $target.DCPrefix
    $newNetbios  = $target.NetBIOSName
    $newSidBase  = $target.SIDBase
    Write-Host "Auto-loaded values from $($jsonFile.Name)"
}

$newDomain   = Read-Host "New domain FQDN"   ; if (!$newDomain)   { Write-Error "Required"; exit }
$newDcPrefix = Read-Host "New DC prefix"    ; if (!$newDcPrefix) { Write-Error "Required"; exit }
$newNetbios  = Read-Host "New NetBIOS name" ; if (!$newNetbios)  { Write-Error "Required"; exit }

$newDcFqdn = "$newDcPrefix.$newDomain"

# SID update
$updateSids = Read-Host "`nUpdate Domain/Enterprise Admins SIDs directly? (y/N)"
$sidReplacements = @{}
if ($updateSids -match '^[yY]') {
    $newSidBase = if ($newSidBase) { $newSidBase } else { Read-Host "New SID base (e.g. 1122334455-6677889900-1234567890)" }
    $oldSidBase = Read-Host "Old SID base (press Enter for 2926635386-1481231937-3050549317)"
    if (!$oldSidBase) { $oldSidBase = "2926635386-1481231937-3050549317" }

    foreach ($rid in 512, 519) {
        $oldSid = "S-1-5-21-$oldSidBase-$rid"
        $newSid = "S-1-5-21-$newSidBase-$rid"
        $sidReplacements[$oldSid] = $newSid
    }
}

$encodingPriority = 'Unicode','UTF8','Default'

$filesToChange = @()

Get-ChildItem -Path $rootPath -Recurse -File | ForEach-Object {
    if ($_.Extension -match '\.pol$|\.csv$') { return }

    $content = $null
    $enc = $null
    foreach ($e in $encodingPriority) {
        try {
            $content = Get-Content $_.FullName -Raw -Encoding $e -ErrorAction Stop
            $enc = $e
            break
        } catch {}
    }
    if (!$content -or $content -match "\0") { return }

    $test = $content

    # Replace literal placeholders from your files
    $test = $test -replace 'NetBiosName', $newNetbios
    $test = $test -replace 'Placeholder', $newNetbios   # used for user and sometimes NetBIOS

    # Standard replacements
    $test = $test -replace [regex]::Escape($oldDomain), $newDomain
    $test = $test -replace [regex]::Escape($oldDcFqdn), $newDcFqdn
    $test = $test -replace [regex]::Escape("\\$oldDcFqdn\"), "\\$newDcFqdn\"
    $test = $test -replace 'ADD YOUR DOMAIN ADMINS', "$newNetbios\Domain Admins"
    $test = $test -replace 'ADD YOUR ENTERPRISE ADMINS', "$newNetbios\Enterprise Admins"

    # SIDs if requested
    foreach ($sid in $sidReplacements.Keys) {
        $test = $test -replace [regex]::Escape($sid), $sidReplacements[$sid]
    }

    if ($test -ne $content) {
        $filesToChange += [pscustomobject]@{
            Path     = $_.FullName
            Content  = $content
            Encoding = $enc
            New      = $test
        }
    }
}

if ($filesToChange.Count -eq 0) {
    Write-Host "No changes needed."
    exit
}

Write-Host "`n$($filesToChange.Count) files will be modified. Applying changes..."

foreach ($f in $filesToChange) {
    Copy-Item $f.Path "$($f.Path).bak" -Force
    Set-Content -Path $f.Path -Value $f.New -Encoding $f.Encoding -NoNewline
    Write-Host "Updated: $($f.Path)"
}

Write-Host "`nDone. All NetBiosName → $newNetbios, Placeholder → $newNetbios, domain/DC/SIDs fixed."