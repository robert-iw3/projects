$lgpoUrl = "https://download.microsoft.com/download/8/5/E/85E2F2B7-6B58-4B4F-9A4F-5D86B00F7D3E/LGPO.zip"
$outZip = Join-Path $PSScriptRoot "LGPO.zip"
$exePath = Join-Path $PSScriptRoot "LGPO.exe"

# If LGPO.exe already exists, skip everything
if (Test-Path $exePath) {
    Write-Host "LGPO.exe is already present in the current directory." -ForegroundColor Green
    exit
}

Write-Host "Downloading LGPO.zip from Microsoft..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $lgpoUrl -OutFile $outZip -UseBasicParsing

if (-not (Test-Path $outZip)) {
    Write-Error "Download failed - file not found."
    exit 1
}

Write-Host "Extracting LGPO.exe to current directory..." -ForegroundColor Cyan
Expand-Archive -Path $outZip -DestinationPath $PSScriptRoot -Force

# Clean up the zip (keeps only LGPO.exe and any supporting files that come with it)
Remove-Item $outZip -Force

Write-Host "LGPO.exe is now ready in:" -ForegroundColor Green
Write-Host $PSScriptRoot -ForegroundColor Yellow