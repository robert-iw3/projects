# syntax=docker/dockerfile:1
# container to test STIG scripts, you will need to run this on a windows system with docker/podman...
# utilize Evaluate-STIG to validate
# change server version if testing another
# https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/container-base-images
FROM mcr.microsoft.com/windows/server:ltsc2025-amd64

LABEL BaseImage="windows/server:ltsc2025-amd64"

ENV container docker
ENV chocolateyUseWindowsCompression false
SHELL ["powershell.exe"]

RUN \
    iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')); \
    choco feature disable --name showDownloadProgress; \
    choco feature enable -n allowGlobalConfirmation; \
    Import-Module $env:ChocolateyInstall\\helpers\\chocolateyProfile.psm1; \
    Write-Host "Install Latest Windows Updates" ; \
    choco install pswindowsupdate; \
    Set-Executionpolicy -ExecutionPolicy RemoteSigned -Force ; \
    Import-Module PSWindowsUpdate -Force ; \
    refreshenv; \
    Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false ; \
    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install ; \
    Get-WuInstall -AcceptAll -IgnoreReboot -IgnoreUserInput -nottitle 'preview' ; \
    Get-WindowsUpdate -Install

COPY . .
#COPY Evaluate-STIG/ .

ENTRYPOINT [ "powershell.exe -File secure-standalone-server.ps1" ]
