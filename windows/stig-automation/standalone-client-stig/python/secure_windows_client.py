import argparse
import datetime
import os
import shutil
import subprocess
import time
import winreg
import psutil
import sys
import glob
from pathlib import Path

# Function to check if script is running as administrator
def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

# Function to execute PowerShell commands
def run_powershell_command(command, timeout=None):
    try:
        result = subprocess.run(
            ["powershell", "-Command", command],
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout
        )
        return result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        print(f"Error executing PowerShell command: {e.stderr}")
        return None, e.stderr
    except subprocess.TimeoutExpired:
        print(f"PowerShell command timed out: {command}")
        return None, "Timeout"

# Function to create a system restore point
def create_restore_point(description):
    min_free_space = 10000000000  # 10GB
    disk = psutil.disk_usage('C:\\')
    if disk.free < min_free_space:
        print(f"Not enough disk space to create a restore point. Current free space: {disk.free / (1024**3):.2f} GB")
        return
    print("Taking a Restore Point Before Continuing....")
    command = f"""
    Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore' -Name 'SystemRestorePointCreationFrequency' -Value 0 -Force;
    Checkpoint-Computer -Description "{description}" -RestorePointType "MODIFY_SETTINGS"
    """
    stdout, stderr = run_powershell_command(command)
    if stderr:
        print(f"Error creating restore point: {stderr}")
    else:
        print("Restore point created successfully.")

# Function to install Group Policy client tools
def install_gpo_packages():
    print("Installing Group Policy Client Tools...")
    command = """
    $mumFiles = Get-ChildItem "$env:SystemRoot\\servicing\\Packages\\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum";
    foreach ($file in $mumFiles) {
        if ((dism /online /get-packages | Where-Object { $_.name -like '*Microsoft-Windows-GroupPolicy-ClientTools*' }).count -eq 0) {
            dism /Online /NoRestart /Add-Package:$file.FullName
        }
    }
    $mumFiles = Get-ChildItem "$env:SystemRoot\\servicing\\Packages\\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum";
    foreach ($file in $mumFiles) {
        if ((dism /online /get-packages | Where-Object { $_.name -like '*Microsoft-Windows-GroupPolicy-ClientExtensions*' }).count -eq 0) {
            dism /Online /NoRestart /Add-Package:$file.FullName
        }
    }
    """
    stdout, stderr = run_powershell_command(command)
    if stderr:
        print(f"Error installing GPO packages: {stderr}")
    else:
        print("GPO packages installed successfully.")

# Function to import GPOs using LGPO.exe
def import_gpos(gpos_dir):
    print(f"Importing Group Policies from {gpos_dir} ...")
    gpos_dir_path = Path(gpos_dir)
    if not gpos_dir_path.exists():
        print(f"Directory {gpos_dir} does not exist.")
        return
    for gpo_item in gpos_dir_path.iterdir():
        if gpo_item.is_dir():
            print(f"Importing {gpo_item.name} GPOs...")
            lgpo_path = Path("Files/LGPO/LGPO.exe")
            if not lgpo_path.exists():
                print(f"LGPO.exe not found at {lgpo_path}")
                return
            try:
                subprocess.run([str(lgpo_path), "/g", str(gpo_item)], check=True, capture_output=True, text=True)
                print(f"Imported {gpo_item.name}")
            except subprocess.CalledProcessError as e:
                print(f"Error importing GPO {gpo_item.name}: {e.stderr}")

# Function to set registry value
def set_registry_value(key, subkey, name, value, vtype=winreg.REG_DWORD):
    try:
        reg_key = winreg.CreateKey(key, subkey)
        winreg.SetValueEx(reg_key, name, 0, vtype, value)
        winreg.CloseKey(reg_key)
        print(f"Set {subkey}\\{name} to {value}")
    except Exception as e:
        print(f"Error setting registry {subkey}\\{name}: {e}")

# Function to create registry subkey
def create_registry_subkey(key, subkey):
    try:
        winreg.CreateKey(key, subkey)
        print(f"Created registry subkey {subkey}")
    except Exception as e:
        print(f"Error creating subkey {subkey}: {e}")

# Main function
def main():
    if not is_admin():
        print("This script requires administrative privileges.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Apply STIGs to Windows client systems")
    parser.add_argument("--cleargpos", type=bool, default=True, help="Clear existing GPOs")
    parser.add_argument("--installupdates", type=bool, default=True, help="Install Windows updates")
    parser.add_argument("--adobe", type=bool, default=True, help="Apply Adobe STIGs")
    parser.add_argument("--firefox", type=bool, default=True, help="Apply Firefox STIGs")
    parser.add_argument("--chrome", type=bool, default=True, help="Apply Chrome STIGs")
    parser.add_argument("--IE11", type=bool, default=True, help="Apply IE11 STIGs")
    parser.add_argument("--edge", type=bool, default=True, help="Apply Edge STIGs")
    parser.add_argument("--dotnet", type=bool, default=True, help="Apply .NET Framework STIGs")
    parser.add_argument("--office", type=bool, default=True, help="Apply Office STIGs")
    parser.add_argument("--onedrive", type=bool, default=True, help="Apply OneDrive STIGs")
    parser.add_argument("--java", type=bool, default=True, help="Apply Java JRE 8 STIGs")
    parser.add_argument("--windows", type=bool, default=True, help="Apply Windows 10/11 STIGs")
    parser.add_argument("--defender", type=bool, default=True, help="Apply Defender STIGs")
    parser.add_argument("--firewall", type=bool, default=True, help="Apply Firewall STIGs")
    parser.add_argument("--mitigations", type=bool, default=True, help="Apply general mitigations")
    parser.add_argument("--nessusPID", type=bool, default=True, help="Fix Nessus PID 63155")
    parser.add_argument("--horizon", type=bool, default=True, help="Apply VMware Horizon STIGs")
    args = parser.parse_args()

    params = [
        args.cleargpos, args.installupdates, args.adobe, args.firefox, args.chrome,
        args.IE11, args.edge, args.dotnet, args.office, args.onedrive, args.java,
        args.windows, args.defender, args.firewall, args.mitigations, args.nessusPID,
        args.horizon
    ]
    if not any(params):
        print("No Options Were Selected. Exiting...")
        sys.exit(1)

    # Set working directory to script location
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # Create restore point if any parameter is True
    if any(params):
        create_restore_point(f"RestorePoint secure_windows_client.py {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Install Group Policy client tools
    if any(params):
        install_gpo_packages()

    # Clear existing GPOs
    if args.cleargpos:
        print("Removing Existing Local GPOs")
        shutil.rmtree(r"C:\Windows\System32\GroupPolicy", ignore_errors=True)
        shutil.rmtree(r"C:\Windows\System32\GroupPolicyUsers", ignore_errors=True)
        run_powershell_command('secedit /configure /cfg "$env:WinDir\\inf\\defltbase.inf" /db defltbase.sdb /verbose')
        run_powershell_command("gpupdate /force")
    else:
        print("The Clear Existing GPOs Section Was Skipped...")

    # Install Windows updates
    if args.installupdates:
        print("Installing the Latest Windows Updates")
        shutil.copytree(r".\Files\PowerShell Modules", r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules", dirs_exist_ok=True)
        command_unblock = """
        Get-ChildItem "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\PSWindowsUpdate\\" -recurse | Unblock-File
        """
        run_powershell_command(command_unblock)
        command_update = """
        Import-Module -Name PSWindowsUpdate -Force -Global;
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot;
        Get-WuInstall -AcceptAll -IgnoreReboot;
        Get-WuInstall -AcceptAll -Install -IgnoreReboot
        """
        run_powershell_command(command_update)
    else:
        print("The Install Update Section Was Skipped...")

    # Apply Adobe STIGs
    if args.adobe:
        print("Implementing the Adobe STIGs")
        import_gpos(r".\Files\GPOs\DoD\Adobe")
        adobe_path = r"Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown"
        for subkey in ["cCloud", "cDefaultLaunchURLPerms", "cServices", "cSharePoint", "cWebmailProfiles", "cWelcomeScreen"]:
            create_registry_subkey(winreg.HKEY_LOCAL_MACHINE, f"{adobe_path}\\{subkey}")
        set_registry_value(winreg.HKEY_LOCAL_MACHINE, r"Software\Adobe\Acrobat Reader\DC\Installer", "DisableMaintenance", 1)
        adobe_settings = [
            ("bAcroSuppressUpsell", 1), ("bDisablePDFHandlerSwitching", 1), ("bDisableTrustedFolders", 1),
            ("bDisableTrustedSites", 1), ("bEnableFlash", 0), ("bEnhancedSecurityInBrowser", 1),
            ("bEnhancedSecurityStandalone", 1), ("bProtectedMode", 1), ("iFileAttachmentPerms", 1),
            ("iProtectedView", 2)
        ]
        for name, value in adobe_settings:
            set_registry_value(winreg.HKEY_LOCAL_MACHINE, adobe_path, name, value)
        set_registry_value(winreg.HKEY_LOCAL_MACHINE, f"{adobe_path}\\cCloud", "bAdobeSendPluginToggle", 1)
        set_registry_value(winreg.HKEY_LOCAL_MACHINE, f"{adobe_path}\\cDefaultLaunchURLPerms", "iURLPerms", 1)
        set_registry_value(winreg.HKEY_LOCAL_MACHINE, f"{adobe_path}\\cDefaultLaunchURLPerms", "iUnknownURLPerms", 3)
        set_registry_value(winreg.HKEY_LOCAL_MACHINE, f"{adobe_path}\\cServices", "bToggleAdobeDocumentServices", 1)
        set_registry_value(winreg.HKEY_LOCAL_MACHINE, f"{adobe_path}\\cServices", "bToggleAdobeSign", 1)
        set_registry_value(winreg.HKEY_LOCAL_MACHINE, f"{adobe_path}\\cServices", "bTogglePrefsSync", 1)
        set_registry_value(winreg.HKEY_LOCAL_MACHINE, f"{adobe_path}\\cServices", "bToggleWebConnectors", 1)
        set_registry_value(winreg.HKEY_LOCAL_MACHINE, f"{adobe_path}\\cServices", "bUpdater", 0)
        set_registry_value(winreg.HKEY_LOCAL_MACHINE, f"{adobe_path}\\cSharePoint", "bDisableSharePointFeatures", 1)
        set_registry_value(winreg.HKEY_LOCAL_MACHINE, f"{adobe_path}\\cWebmailProfiles", "bDisableWebmail", 1)
        set_registry_value(winreg.HKEY_LOCAL_MACHINE, f"{adobe_path}\\cWelcomeScreen", "bShowWelcomeScreen", 0)
        set_registry_value(winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer", "DisableMaintenance", 1)
    else:
        print("The Adobe Section Was Skipped...")

    # Apply Firefox STIGs
    if args.firefox:
        print("Implementing the FireFox STIGs")
        import_gpos(r".\Files\GPOs\DoD\FireFox")
        import_gpos(r".\Files\GPOs\SoS\FireFox")
        firefox64 = r"C:\Program Files\Mozilla Firefox"
        firefox32 = r"C:\Program Files (x86)\Mozilla Firefox"
        for path in [firefox64, firefox32]:
            if os.path.exists(path):
                shutil.copytree(r".\Files\FireFox Configuration Files\defaults", os.path.join(path, "defaults"), dirs_exist_ok=True)
                shutil.copy2(r".\Files\FireFox Configuration Files\mozilla.cfg", path)
                shutil.copy2(r".\Files\FireFox Configuration Files\local-settings.js", path)
                print(f"Firefox {'64-Bit' if path == firefox64 else '32-Bit'} Configurations Installed")
            else:
                print(f"FireFox {'64-Bit' if path == firefox64 else '32-Bit'} Is Not Installed")
    else:
        print("The FireFox Section Was Skipped...")

    # Apply Chrome STIGs
    if args.chrome:
        print("Implementing the Google Chrome STIGs")
        import_gpos(r".\Files\GPOs\DoD\Chrome")
    else:
        print("The Google Chrome Section Was Skipped...")

    # Apply IE11 STIGs
    if args.IE11:
        print("Implementing the Internet Explorer 11 STIGs")
        import_gpos(r".\Files\GPOs\DoD\IE11")
    else:
        print("The Internet Explorer 11 Section Was Skipped...")

    # Apply Edge STIGs
    if args.edge:
        print("Implementing the Microsoft Edge STIGs")
        import_gpos(r".\Files\GPOs\DoD\Edge")
        create_registry_subkey(winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\MicrosoftEdge\Main")
        set_registry_value(winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\MicrosoftEdge\Main", "AllowInPrivate", 0)
        create_registry_subkey(winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\MicrosoftEdge\Privacy")
        set_registry_value(winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\MicrosoftEdge\Privacy", "ClearBrowsingHistoryOnExit", 0)
    else:
        print("The Microsoft Edge Section Was Skipped...")

    # Apply .NET Framework STIGs
    if args.dotnet:
        print("Implementing the Dot Net Framework STIGs")
        try:
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\StrongName\Verification")
            print(".Net StrongName Verification Registry Removed")
        except FileNotFoundError:
            print(".Net StrongName Verification Registry Does Not Exist")
        command_sids = """
        New-PSDrive HKU Registry HKEY_USERS | Out-Null;
        ForEach ($UserSID in (Get-ChildItem \"HKU:\\\")) {
            $SID = $UserSID.Name -split '\\\\' | Select-Object -Last 1;
            $path = \"HKU:\\$SID\\Software\\Microsoft\\Windows\\CurrentVersion\\WinTrust\\Trust Providers\\Software Publishing\";
            if (Test-Path $path) {
                Set-ItemProperty -Path $path -Name \"State\" -Value 0x23C00 -Force;
            } else {
                New-Item -Path $path -Force;
                New-ItemProperty -Path $path -Name \"State\" -Value 0x23C00 -Force;
            }
        }
        """
        run_powershell_command(command_sids)
        netframework32 = r"C:\Windows\Microsoft.NET\Framework"
        netframework64 = r"C:\Windows\Microsoft.NET\Framework64"
        for base, wow in [(netframework32, False), (netframework64, True)]:
            for version_dir in glob.glob(os.path.join(base, "v*")):
                version = os.path.basename(version_dir)
                print(f".Net {'32-Bit' if not wow else '64-Bit'} {version} Is Installed")
                caspol_path = os.path.join(version_dir, "caspol.exe")
                if os.path.exists(caspol_path):
                    subprocess.run([caspol_path, "-q", "-f", "-pp", "on"], capture_output=True)
                    subprocess.run([caspol_path, "-m", "-lg"], capture_output=True)
                    print(f"Set CAS policy for {version} {'32-Bit' if not wow else '64-Bit'}")
                set_registry_value(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\.NETFramework", "AllowStrongNameBypass", 0)
                reg_path = r"SOFTWARE\Wow6432Node\Microsoft\.NETFramework" if wow else r"SOFTWARE\Microsoft\.NETFramework"
                create_registry_subkey(winreg.HKEY_LOCAL_MACHINE, f"{reg_path}\\{version}")
                set_registry_value(winreg.HKEY_LOCAL_MACHINE, f"{reg_path}\\{version}", "SchUseStrongCrypto", 1)
    else:
        print("The Dot Net Framework Section Was Skipped...")

    # Apply Office STIGs
    if args.office:
        print("Implementing the Microsoft Office STIGs")
        import_gpos(r".\Files\GPOs\DoD\Office")
    else:
        print("The Microsoft Office Section Was Skipped...")

    # Apply OneDrive STIGs
    if args.onedrive:
        print("Implementing the Microsoft OneDrive STIGs")
        import_gpos(r".\Files\GPOs\SoS\Onedrive")
    else:
        print("The OneDrive Section Was Skipped...")

    # Apply Java JRE 8 STIGs
    if args.java:
        print("Implementing the Oracle Java JRE 8 STIGs")
        java_deployment = r"C:\Windows\Sun\Java\Deployment"
        if not os.path.exists(java_deployment):
            os.makedirs(java_deployment)
            shutil.copy2(r".\Files\JAVA Configuration Files\deployment.config", java_deployment)
            print("JAVA Deployment Config Installed")
        java_configs = r"C:\Windows\Java\Deployment"
        if not os.path.exists(java_configs):
            os.makedirs(java_configs)
            shutil.copy2(r".\Files\JAVA Configuration Files\deployment.properties", java_configs)
            shutil.copy2(r".\Files\JAVA Configuration Files\exception.sites", java_configs)
            print("JAVA Configs Installed")
    else:
        print("The Oracle Java JRE 8 Section Was Skipped...")

    # Apply Windows 10/11 STIGs
    if args.windows:
        print("Implementing the Windows 10/11 STIGs")
        import_gpos(r".\Files\GPOs\DoD\Windows")
        os.makedirs(r"C:\temp", exist_ok=True)
        shutil.copy2(r".\Files\auditing\auditbaseline.csv", r"C:\temp\auditbaseline.csv")
        run_powershell_command("auditpol /clear /y")
        run_powershell_command("auditpol /restore /file:C:\\temp\\auditbaseline.csv")
        run_powershell_command("auditpol /list /user /v")
        run_powershell_command("auditpol.exe /get /category:*")
        windows_settings = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\Internet Explorer\Feeds", "AllowBasicAuthInClear", 0),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing", "State", 146432),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing", "State", 146432),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\Internet Explorer\Main Criteria", "Use FormSuggest", "no", winreg.REG_SZ),
            (winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Internet Explorer\Main Criteria", "Use FormSuggest", "no", winreg.REG_SZ),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\Internet Explorer\Main Criteria", "FormSuggest PW Ask", "no", winreg.REG_SZ),
            (winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Internet Explorer\Main Criteria", "FormSuggest PW Ask", "no", winreg.REG_SZ),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002", "EccCurves", ["NistP384", "NistP256"], winreg.REG_MULTI_SZ),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments", "SaveZoneInformation", 2),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments", "SaveZoneInformation", 2),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications", "NoToastApplicationNotificationOnLockScreen", 1),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications", "NoToastApplicationNotificationOnLockScreen", 1),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableThirdPartySuggestions", 1),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableThirdPartySuggestions", 1),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy", "LetAppsActivateWithVoice", 2),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoReadingPane", 1),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoReadingPane", 1),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\PassportForWork", "RequireSecurityDevice", 1)
        ]
        for key, subkey, name, value, *vtype in windows_settings:
            create_registry_subkey(key, subkey)
            set_registry_value(key, subkey, name, value, vtype[0] if vtype else winreg.REG_DWORD)
    else:
        print("The Windows Desktop Section Was Skipped...")

    # Apply Defender STIGs
    if args.defender:
        print("Implementing the Windows Defender STIGs")
        import_gpos(r".\Files\GPOs\DoD\Defender")
    else:
        print("The Windows Defender Section Was Skipped...")

    # Apply Firewall STIGs
    if args.firewall:
        print("Implementing the Windows Firewall STIGs")
        import_gpos(r".\Files\GPOs\DoD\FireWall")
    else:
        print("The Windows Firewall Section Was Skipped...")

    # Apply General Mitigations
    if args.mitigations:
        print("Implementing the General Vulnerability Mitigations")
        mitigation_settings = [
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "FeatureSettingsOverride", 72),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "FeatureSettingsOverrideMask", 3),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Virtualization", "MinVmVersionForCpuBasedMitigations", "1.0", winreg.REG_SZ),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Explorer", "NoDataExecutionPrevention", 0),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "DisableHHDEP", 0),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", "DisableExceptionChainValidation", 0),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad", "WpadOverride", 1),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad", "WpadOverride", 1),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe", "AuditLevel", 8),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Script Host\Settings", "Enabled", 0),
            (winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\SecurityProviders\Wdigest", "UseLogonCredential", 0),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel", "MitigationOptions", 0x1000000000000, winreg.REG_QWORD)
        ]
        for key, subkey, name, value, *vtype in mitigation_settings:
            create_registry_subkey(key, subkey)
            set_registry_value(key, subkey, name, value, vtype[0] if vtype else winreg.REG_DWORD)
        subprocess.run(["netsh", "int", "tcp", "set", "global", "timestamps=disabled"], capture_output=True)
        run_powershell_command("BCDEDIT /set {current} nx OptOut")
        run_powershell_command("Set-Processmitigation -System -Enable DEP")
        command_netbios = """
        $key = 'HKLM:SYSTEM\\CurrentControlSet\\services\\NetBT\\Parameters\\Interfaces';
        Get-ChildItem $key | ForEach-Object { Set-ItemProperty -Path \"$key\\$($_.pschildname)\" -Name 'NetbiosOptions' -Value 2 }
        """
        run_powershell_command(command_netbios)
        office_versions = ['16.0', '15.0', '14.0', '12.0']
        for ver in office_versions:
            for key in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                create_registry_subkey(key, f"SOFTWARE\\Microsoft\\Office\\{ver}\\Outlook\\Security")
                set_registry_value(key, f"SOFTWARE\\Microsoft\\Office\\{ver}\\Outlook\\Security", "ShowOLEPackageObj", 0)
        run_powershell_command("powercfg -h off")
    else:
        print("The General Mitigations Section Was Skipped...")

    # Fix Nessus PID 63155
    if args.nessusPID:
        print("Resolve: Nessus Plugin ID 63155 - Microsoft Windows Unquoted Service Path Enumeration")
        command_nessus = """
        $FixParameters = @(@{Path='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\'; ParamName='ImagePath'}, @{Path='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\'; ParamName='UninstallString'});
        if (Test-Path \"$($env:SystemDrive)\\Program Files (x86)\\\") {
            $FixParameters += @{Path='HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\'; ParamName='UninstallString'}
        }
        foreach ($FixParameter in $FixParameters) {
            Get-ChildItem $FixParameter.Path -ErrorAction SilentlyContinue | ForEach-Object {
                $RegistryPath = $_.name -Replace 'HKEY_LOCAL_MACHINE', 'HKLM:' -replace '([\\[\\]])', '`$1';
                $OriginalPath = Get-ItemProperty $RegistryPath;
                $ImagePath = $OriginalPath.$($FixParameter.ParamName);
                if (($ImagePath -like '* *') -and ($ImagePath -notLike '"*"*') -and ($ImagePath -like '*.exe*')) {
                    if ((($FixParameter.ParamName -eq 'UninstallString') -and ($ImagePath -NotMatch 'MsiExec(\\.exe)?') -and ($ImagePath -Match '^((\\w\\:)|(%[-\\w_()]+%))\\\\')) -or ($FixParameter.ParamName -eq 'ImagePath')) {
                        $NewPath = ($ImagePath -split \".exe \")[0];
                        $key = ($ImagePath -split \".exe \")[1];
                        $NewValue = if ($key) { '\"' + $NewPath + '.exe\" ' + $key } else { '\"' + $NewPath + '.exe\"' };
                        Set-ItemProperty -Path $RegistryPath -Name $FixParameter.ParamName -Value $NewValue -ErrorAction Stop;
                    }
                }
            }
        }
        """
        run_powershell_command(command_nessus)
    else:
        print("The Nessus PID 63155 Section Was Skipped...")

    # Apply VMware Horizon STIGs
    if args.horizon:
        print("Implementing the VMWare Horizon STIG Configurations")
        import_gpos(r".\Files\GPOs\DoD\Horizon")
    else:
        print("The VMware Horizon STIG Section Was Skipped...")

    # Perform Group Policy Update
    print("Performing Group Policy Update")
    timeout_seconds = 180
    process = subprocess.Popen(["powershell", "-Command", "gpupdate /force"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        if process.returncode == 0:
            print("Group Policy Update completed.")
        else:
            print(f"Group Policy Update failed: {stderr}")
    except subprocess.TimeoutExpired:
        process.kill()
        print(f"Group Policy Update timed out after {timeout_seconds} seconds.")

    print("WARNING: A reboot is required for all changes to take effect")

if __name__ == "__main__":
    main()