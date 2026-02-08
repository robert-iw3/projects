# syntax=docker/dockerfile:1
# Container to test STIG scripts for Windows 10/11 clients, must be run on a Windows system with Docker Desktop or Podman.
# Uses Windows 10 LTSC 2021 as the base image due to the lack of official Windows 11 container images.
# The script is designed for Windows 11 hardening but is compatible with this image for testing.
# Use Evaluate-STIG to validate compliance.
# https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/container-base-images
FROM mcr.microsoft.com/windows:10.0.19044.4529-ltsc2022-amd64

LABEL BaseImage="windows:10.0.19044.4529-ltsc2022-amd64"

ENV container docker
SHELL ["powershell.exe", "-Command"]

RUN \
    Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe -OutFile python-installer.exe; \
    Start-Process -FilePath python-installer.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait; \
    Remove-Item python-installer.exe

RUN pip install psutil pywin32

COPY . .

ENTRYPOINT ["python.exe", "secure_windows_client.py"]