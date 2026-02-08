# syntax=docker/dockerfile:1
# Container to test STIG scripts, must be run on a Windows system with Docker/Podman.
# Utilize Evaluate-STIG to validate.
# Change server version if testing another.
# https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/container-base-images
FROM mcr.microsoft.com/windows/server:ltsc2025-amd64

LABEL BaseImage="windows/server:ltsc2025-amd64"

ENV container docker
SHELL ["powershell.exe", "-Command"]

RUN \
    Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe -OutFile python-installer.exe; \
    Start-Process -FilePath python-installer.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait; \
    Remove-Item python-installer.exe

RUN pip install psutil pywin32

COPY . .

ENTRYPOINT ["python.exe", "secure_standalone_server.py"]