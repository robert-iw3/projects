#  Windows_STIG_Ansible

Ansible Playbooks for Windows STIG Scripts


## Notes:
- Offline support is supported. Modify collections/ansible_collections/ansible/windows_stigs/playbooks/roles/<stig dir's>/vars/main.yml
  gitrepo: "point to download url for powershell hardening scripts associated with the STIG"
- Ansible galaxy collection does not include the offline copies of the dependencies

## Requirements:
- Requires you have secure WinRM over HTTPS already configured on your Windows Systems
  - STIGs mandate you have WinRM over HTTPs if you use WinRM. This in mind, this collection enforces changes that enforce WinRM over HTTPs. If you're using plaintext WinRM this collection will break your communication with your windows hosts.
  - Read the following for more information:
    - [Ansible - Setting up a Windows Host](https://docs.ansible.com/ansible/2.5/user_guide/windows_setup.html)
    - [Microsoft - Security Considerations for PowerShell Remoting using WinRM](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/winrmsecurity?view=powershell-7.2)
    - [Microsoft - How to configure WINRM for HTTPS](https://docs.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/configure-winrm-for-https)
 - Must be using a domain account for your ansible user
   - UAC is enforced with implementing STIGs and with this Collection
   - With UAC enabled, winrm disallows all local accounts even with specific exceptions

## Installation:

```bash
ansible-galaxy collection install ansible.windows_stigs
```
## Usage:

```bash
# update the host vars, enable WinRM over https on target host(s)

# example run of adobe stig playbook

# view tasks of a playbook
ansible-playbook collections/ansible_collections/ansible/windows_stigs/playbooks/adobe-reader-dc-stig.yml --list-tasks

# run playbook
ansible-playbook collections/ansible_collections/ansible/windows_stigs/playbooks/adobe-reader-dc-stig.yml
```


