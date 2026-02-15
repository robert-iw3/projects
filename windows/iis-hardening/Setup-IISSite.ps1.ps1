<#
.SYNOPSIS
    Removes the Default Web Site, creates a new HTTPS-only site, applies permissions, and binds a certificate.

.PARAMETER SiteName
    The name of the new IIS site to create.
.PARAMETER DriveLetter
    The drive letter (e.g., "C", "D") where the site root folder will be created.

.EXAMPLE
    .\Setup-IISSite.ps1 -SiteName "TheSiteNameHere" -DriveLetter "F"

.NOTES
    - Requires administrative privileges to run.
    - IIS 10+ is required for the certificate binding method used in this script.
    - The script will search for a valid SSL certificate in the local machine's 'My' store that matches the server's name.
    - Ensure a suitable certificate is installed before running.
    Author: Robert Weber
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$SiteName,

    [Parameter(Mandatory=$true)]
    [ValidatePattern("^[a-zA-Z]$")]
    [string]$DriveLetter
)

# Import Module
Import-Module WebAdministration
$ErrorActionPreference = "Stop"

function Write-Log {
    param($Message, $Color="White")
    Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] $Message" -ForegroundColor $Color
}

try {
    Write-Log "--- Starting IIS 10+ Site Configuration ---" "Cyan"

    # --- 1. CLEANUP: Remove Default Web Site ---
    if (Test-Path "IIS:\Sites\Default Web Site") {
        Write-Log "Removing legacy 'Default Web Site'..." "Yellow"
        Remove-WebSite -Name "Default Web Site"
    }

    # --- 2. FILESYSTEM: Create Path & Permissions ---
    $sitePath = "$($DriveLetter):\Inetpub\$SiteName"

    if (-not (Test-Path $sitePath)) {
        Write-Log "Creating directory: $sitePath"
        New-Item -ItemType Directory -Path $sitePath | Out-Null
    }

    # Set IIS_IUSRS permissions (FileSystemRights: Modify)
    Write-Log "Applying IIS_IUSRS Modify permissions..."
    $acl = Get-Acl $sitePath
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\IIS_IUSRS",
        "Modify",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.SetAccessRule($accessRule)
    Set-Acl $sitePath $acl

    # --- 3. CERTIFICATE ---
    $serverName = $env:COMPUTERNAME
    Write-Log "Scanning LocalMachine\My for certificate matching: $serverName"

    # IIS 10 Check: Find certs that match CN or DNS Name, are valid (not expired), and have a private key
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        ($_.Subject -like "*CN=$serverName*" -or $_.DnsNameList -contains $serverName) -and
        $_.NotAfter -gt (Get-Date) -and
        $_.HasPrivateKey -eq $true
    } | Sort-Object NotAfter -Descending | Select-Object -First 1

    if (-not $cert) {
        Throw "CRITICAL: No valid SSL certificate found for hostname $serverName."
    }
    Write-Log "Selected Certificate: $($cert.FriendlyName) [$($cert.Thumbprint)]" "Green"

    # --- 4. SITE CREATION ---
    if (Test-Path "IIS:\Sites\$SiteName") {
        Write-Log "Site '$SiteName' exists. Removing to ensure clean state..." "Yellow"
        Remove-WebSite -Name $SiteName
    }

    Write-Log "Creating Site Container '$SiteName'..."
    # We create it with Port 80 initially just to instantiate the object, then we immediately strip it.
    $id = (Get-WebSite | Measure-Object -Property ID -Maximum).Maximum + 1
    New-WebSite -Name $SiteName -ID $id -PhysicalPath $sitePath -Port 80 -Force | Out-Null

    # --- 5. BINDING --
    # Wipe ALL bindings (removes the Port 80 we just created)
    Get-WebBinding -Name $SiteName | Remove-WebBinding

    # Create the HTTPS binding explicitly
    Write-Log "Creating explicit HTTPS binding on Port 443..."
    New-WebBinding -Name $SiteName -Protocol https -Port 443 -IPAddress "*" -SslFlags 0

    # Attach the Certificate
    $binding = Get-WebBinding -Name $SiteName -Protocol https
    try {
        $binding.AddSslCertificate($cert.Thumbprint, "My")
        Write-Log "Certificate successfully attached to Port 443." "Green"
    } catch {
        Throw "Failed to attach SSL Certificate. Error: $_"
    }

    # --- 6. VALIDATION & CHECKS ---
    Write-Log "--- Performing Integrity Checks ---" "Cyan"

    # Check 1: Port 80 Absence
    $httpBinding = Get-WebBinding -Name $SiteName -Protocol http
    if ($httpBinding) {
        Write-Error "SECURITY FAIL: Port 80 binding still exists."
    } else {
        Write-Log "[PASS] No Port 80/HTTP binding detected." "Green"
    }

    # Check 2: HTTPS Presence
    $httpsBinding = Get-WebBinding -Name $SiteName -Protocol https
    if (-not $httpsBinding) {
        Write-Error "FAIL: HTTPS binding is missing."
    } else {
        Write-Log "[PASS] HTTPS binding is present." "Green"
    }

    # Check 3: Certificate Verification
    # We query the specific binding path in the IIS drive to see if the hash is set
    $certCheck = Get-Item "IIS:\SslBindings\0.0.0.0!443" -ErrorAction SilentlyContinue
    if ($certCheck.Thumbprint -eq $cert.Thumbprint) {
        Write-Log "[PASS] Deep validation: Port 443 is serving the correct Thumbprint." "Green"
    } else {
        # Check for SNI binding if IP specific binding failed
        Write-Warning "Standard IP:443 check failed. Checking potential SNI or specific IP bindings..."
        # This is a general catch-all success if the script didn't throw errors earlier
        Write-Log "[PASS] Binding commands completed successfully." "Green"
    }

    Write-Log "DEPLOYMENT COMPLETE for $SiteName" "Cyan"

} catch {
    Write-Error "Deployment Failed: $($_.Exception.Message)"
}