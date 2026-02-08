# Hardening Windows Standalone Servers with Python

## Purpose
This project applies Security Technical Implementation Guides (STIGs) to harden Windows Server 2012, 2016, or 2019 for FISMA compliance, automating ~95% of required configuration changes using a Python script.

## Prerequisites
- Windows system with Python 3.11+ installed (including psutil and pywin32 via pip).
- Administrative privileges.
- BitLocker suspended or disabled (re-enable after reboot).
- Hardware meeting [Microsoft's secure device standards](https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-highly-secure).
- 10GB free disk space for system restore point.
- Docker/Podman for testing (optional).

## Setup
1. Clone or download this repository.
2. Ensure `Files` directory contains:
   - `LGPO\LGPO.exe` for Group Policy imports.
   - `GPOs\DoD` and `GPOs\SoS` for STIG policies.
   - `auditing\auditbaseline.csv` for audit policies.
   - `FireFox Configuration Files`, `JAVA Configuration Files`, `PowerShell Modules\PSWindowsUpdate`.
3. Install Python dependencies:
   ```bash
   pip install psutil pywin32
   ```

## Running the Script
Run the script directly on the host OS with administrative privileges. Parameters default to `True`:
```bash
python secure_standalone_server.py --firefox False --chrome False
```
Available parameters (all optional):
- `--cleargpos`: Clear unused GPOs.
- `--installupdates`: Install Windows updates.
- `--adobe`, `--firefox`, `--chrome`, `--ie11`, `--edge`, `--dotnet`, `--office`, `--onedrive`, `--java`, `--windows`, `--defender`, `--firewall`, `--mitigations`, `--nessuspid`, `--horizon`, `--sosoptional`: Apply specific STIGs/mitigations.

## Testing with Docker
The Dockerfile builds a container for testing the script on a Windows Server 2025 base image. It does not apply changes to the host OS.
1. Build the image:
   ```powershell
   docker build -t windows-stig-test .
   ```
2. Run the container (changes apply only inside the container):
   ```powershell
   docker run --rm windows-stig-test --firefox False
   ```
Use for validation; actual hardening must run on the host OS.

## Post-Execution
- Reboot to apply changes.
- Validate with [Evaluate-STIG](https://public.cyber.mil/stigs/evaluate-stig/).
- Re-enable BitLocker.

## Notes
- Supported on Windows Server 2012/2016/2019/2022/2025.
- Manual steps may be needed for 100% compliance.
- Ensure all support files are present.
- A restore point is created if space allows.