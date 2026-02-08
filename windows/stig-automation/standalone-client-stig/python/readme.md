# Hardening Windows Client Systems with Python

## Purpose
This project applies Security Technical Implementation Guides (STIGs) to harden Windows 10/11 client operating systems, with a focus on Windows 11, for FISMA compliance, automating ~95% of required configuration changes using a Python script.

## Prerequisites
- Windows 10/11 client OS (Windows 11 recommended for hardening).
- Python 3.11+ installed.
- Python packages: `psutil`, `pywin32` (install via `pip install psutil pywin32`).
- Administrative privileges.
- BitLocker suspended or disabled (re-enable after reboot).
- Hardware meeting [Microsoft's secure device standards](https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-highly-secure).
- 10GB free disk space for system restore point.
- Docker Desktop or Podman for testing (optional).

## Setup
1. Clone or download this repository.
2. Ensure the `Files` directory contains:
   - `LGPO\LGPO.exe` for Group Policy imports.
   - `GPOs\DoD` and `GPOs\SoS` for STIG policies.
   - `auditing\auditbaseline.csv` for audit policies.
   - `FireFox Configuration Files` for Firefox settings.
   - `JAVA Configuration Files` for Java JRE settings.
   - `PowerShell Modules\PSWindowsUpdate` for Windows updates.
3. Install Python dependencies:
   ```bash
   pip install psutil pywin32
   ```

## Running the Script
Run the script directly on the host Windows 11 (or Windows 10) OS with administrative privileges. All parameters default to `True`:
```bash
python secure_windows_client.py --firefox False --chrome False
```
Available parameters:
- `--cleargpos`: Clear existing Group Policies.
- `--installupdates`: Install Windows updates.
- `--adobe`: Apply Adobe Acrobat Reader STIGs.
- `--firefox`: Apply Firefox STIGs.
- `--chrome`: Apply Google Chrome STIGs.
- `--IE11`: Apply Internet Explorer 11 STIGs.
- `--edge`: Apply Microsoft Edge STIGs.
- `--dotnet`: Apply .NET Framework STIGs.
- `--office`: Apply Microsoft Office STIGs.
- `--onedrive`: Apply OneDrive STIGs.
- `--java`: Apply Oracle Java JRE 8 STIGs.
- `--windows`: Apply Windows 10/11 STIGs.
- `--defender`: Apply Windows Defender STIGs.
- `--firewall`: Apply Windows Firewall STIGs.
- `--mitigations`: Apply general vulnerability mitigations.
- `--nessusPID`: Fix Nessus Plugin ID 63155 (unquoted service paths).
- `--horizon`: Apply VMware Horizon STIGs.

## Testing with Docker
The `Dockerfile` builds a Windows 10 LTSC 2021 container for testing the script, as official Windows 11 base images are not currently available. Changes apply only inside the container, not the host OS.
1. Build the image:
   ```powershell
   docker build -t windows-client-stig-test .
   ```
2. Run the container:
   ```powershell
   docker run --rm windows-client-stig-test --firefox False
   ```

## Post-Execution
- Reboot the host OS to apply changes.
- Validate compliance using [Evaluate-STIG](https://public.cyber.mil/stigs/evaluate-stig/).
- Re-enable BitLocker if needed.

## Notes
- Run the script on the host Windows 11 (or Windows 10) OS for actual hardening.
- Docker testing uses Windows 10 LTSC 2021 due to the lack of official Windows 11 container images, but the script is fully compatible with Windows 11.
- Ensure all support files are present in the `Files` directory.
- A system restore point is created if sufficient disk space is available.
- Some manual configuration may be required for full STIG compliance.