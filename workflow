sysinternal tools setup
Recommended workflow for persistence/malware hunt:
Run Autoruns first → identify suspicious autostarts
Use Process Explorer to inspect those processes live
Fire up ProcMon (with filters) to watch what they do
Check connections with TCPView
enable Sysmon for deeper/long-term logging
Windows Persistence Paths/Locations
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers
HKCR\CLSID
%AppData%\Microsoft\Windows\Start Menu\Programs\Startup
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
%SystemRoot%\System32\Tasks
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
C:\Windows\System32\sethc.exe
C:\Windows\System32\utilman.exe
C:\Windows\System32\magnify.exe
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
Linux Persistence Paths/Locations
/etc/crontab
/etc/cron.d/
/etc/cron.hourly/
/etc/cron.daily/
/etc/cron.weekly/
/etc/cron.monthly/
/var/spool/cron/crontabs/
/var/spool/at/
/etc/at.allow
/etc/at.deny
/etc/systemd/system/
/lib/systemd/system/
/usr/lib/systemd/system/
~/.config/systemd/user/
/etc/init.d/
/etc/rc0.d/
/etc/rc1.d/
/etc/rc2.d/
/etc/rc3.d/
/etc/rc4.d/
/etc/rc5.d/
/etc/rc6.d/
/etc/rc.local
/lib/systemd/system-generators/
~/.bashrc
~/.bash_profile
~/.profile
/etc/bash.bashrc
/etc/profile
/etc/profile.d/
~/.bash_login
~/.ssh/authorized_keys
/etc/pam.d/
/lib/security/
/etc/passwd
/etc/shadow
Order of Volatility (from RFC 3227 – collect in this order!)
Registers, CPU cache
Routing table, ARP cache, process table, kernel stats, memory (RAM)
Temporary file systems (e.g. RAM disks, /tmp in some cases)
Disk (persistent storage)
Remote logging and monitoring data
Physical configuration, network topology
Archival media (backups, tapes – least volatile)
Always collect most volatile first to avoid losing evidence.
Windows Persistence & Hunting Commands
File & Directory Searches
dir /R → Recursive directory listing
dir /a /s searchterm* → Search for files/folders (including hidden) recursively
more < filename → View contents (works on some hidden/alternate streams)
Alternate Data Streams (ADS):
echo "hidden data" > normalfile.txt:HiddenInfo.txt
Get-Content reminder.txt -Stream secret.info
Registry & Boot Config
Get-Item → View specific registry key + properties
reg query HKLM\... → Query registry
Boot Configuration Data (BCD):
bcdedit → View boot config
bcdedit /export C:\backup\BCD → Backup current BCD
bcdedit /import C:\backup\BCD → Restore
bcdedit /deletevalue {current} valuename → Remove value
MBR boot signature check (on Linux): sudo xxd -l 512 -g 1 /dev/sda
Services & Processes
Get-CimInstance -ClassName Win32_Service | Select DisplayName → List services
Get-Service name | Format-List * → Full service details
sc query / sc queryex type= service state= all → All services (running/stopped)
sc qdescription <service> → Service description
tasklist /m → Processes + loaded DLLs
Get-Process / Get-Process | Select Name, Id, Description | Sort Id | more
netstat -ano → Connections, listening ports, owning PID
Get-NetTCPConnection -State Established,Listen → Active/listening TCP
Get-NetTCPConnection | Select LocalPort, RemoteAddress, State, OwningProcess
Get-Process -Id <PID>
Auto-Start / Run Keys (Persistence at Logon)
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
Per-user: HKU<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Services (registry-backed): HKLM\SYSTEM\CurrentControlSet\Services
PowerShell Profiles (Persistence via $PROFILE)
$PROFILE → Current user's profile script path
Common profiles:
AllUsersAllHosts
AllUsersCurrentHost
CurrentUserCurrentHost
CurrentUserAllHost
Always check profiles — they can run scripts on load.
Other Windows Artifacts
Prefetch: C:\Windows\Prefetch — First-run evidence
RecentDocs: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
Jump Lists & AppData\Roaming → Frequent/recent apps & files
Event Logs: Get-EventLog, Get-WinEvent, wevtutil
Key IDs: 4103 (verbose cmd), 4104 (script block), 4105/4106 (engine start/stop)
Auditing: auditpol /get /category:*
Linux Persistence & Hunting Commands
Boot & Init
GRUB: /boot/grub/grub.cfg, /boot/grub/x86_64-efi/normal.mod
Init: /etc/inittab, /etc/rc#.d/ (runlevel scripts)
Kernel modules: lsmod
Systemd: /lib/systemd/system/, systemctl list-units --type=service, systemctl list-timers --all
Processes & Services
ps --ppid 2 -lf | head → Processes from init/systemd (PID 1 or 2)
top / htop → Interactive (sort by PID, look for orphans)
/proc/<PID>/exe → Inspect running binary
sudo lsof -i :<port> → Port → process
sudo lsof -p <PID> → Open files by PID
netstat -tulpn → Listening ports + PID/program
netstat -tulpn | grep -E ':(80|443)' → Suspicious web servers
Logs
journalctl -e → Recent entries
journalctl -u ssh.service → Filter by unit
journalctl -b → Current boot
journalctl --since "2 days ago"
General Tools (Sysinternals & Others – Windows)
AutoRuns → Best for boot/startup persistence (registry + files)
Process Monitor → PPID & behavior tracking
TCPView → Network connections
Process Explorer → Detailed process info
PsExec → -s (system), -i (interactive), -c (copy)
PsLoggedOn → Logged-on users
Handle → Open handles (files, keys, etc.)
ListDLLs → listdlls.exe <process>
Sigcheck → sigcheck -m <exe> (signature + version)
Strings → Extract text from binaries
Memory Forensics Methodology (Quick Checklist)
Identify rogue processes: pslist vs psscan (hidden/misspelled)
Analyze DLLs & handles: dlllist, dlldump
Network artifacts: connections list
Code injection: malfind
Dump suspicious: procdump, memdump, filescan, svcscan
Rootkit hunt: psscan, devicetree
Active Directory / User Hunting (PowerShell)
Expired but enabled accounts (last names, comma-separated):
(Get-ADUser -Filter {Enabled -eq $true} -Properties AccountExpirationDate | Where-Object {$_.AccountExpirationDate -lt (Get-Date) -and $_.AccountExpirationDate -ne $null} | Sort-Object Surname | Select -Expand Surname) -join ','
Find by email: Get-ADUser -Filter {Mail -eq 'user@domain.com'} -Properties Name,Mail
Password never expires: Search-ADAccount -PasswordNeverExpires | Where Enabled
Reversible encryption: Get-ADUser -Filter 'userAccountControl -band 128'
filter ad accounts based on description powershell
Get-ADUser -Properties Description -Filter 'Description -like "*"' | Select Name, SamAccountName, Description
find two accounts with password not expire
Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true -and Name -ne "andy.dwyer"' -Properties PasswordNeverExpires | Select-Object Name, DistinguishedName
one account with reversiblie encryption enable
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth | Select-Object Name, DistinguishedName
# Alternatively, to check specifically for reversible encryption set via policy (requires checking userAccountControl flags):
Get-ADUser -Filter 'UserAccountControl -band 128' -Properties UserAccountControl | Select-Object Name, DistinguishedName
> Get-LocalUser | Where-Object { $_.Name -like "tiff*" }
Windows – Top Persistence Hunting Commands (PowerShell preferred)
AutoRuns is king → Download Sysinternals Autoruns → run as admin → hide Microsoft / Windows entries → look for anything odd (unsigned, unusual path, user-writable locations).
Run / RunOnce keys (logon persistence – very common)PowerShellGet-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | fl *
Scheduled Tasks (high privilege, stealthy)PowerShellGet-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\Windows\*"} | Select TaskName, TaskPath, State, Author, Description, Actions | fl
# Or raw XML dump (shows hidden / deleted tasks sometimes)
Get-ChildItem -Path "C:\Windows\System32\Tasks" -Recurse | ForEach { [xml](Get-Content $_.FullName) } | Select -ExpandProperty Task | Select Actions, Principals, Triggers
Services (kernel/user-mode persistence)PowerShellGet-CimInstance Win32_Service | Where StartName -notlike "LocalSystem" -and StartName -notlike "NT AUTHORITY\*" | Select Name, DisplayName, PathName, StartName, StartMode | Sort PathName
# Suspicious path hunting
Get-WmiObject Win32_Service | ? {$_.PathName -like "*%*" -or $_.PathName -like "*powershell*" -or $_.PathName -like "*cmd*"} | Select Name, PathName
WMI Event Subscriptions (very stealthy, no file on disk sometimes)PowerShellGet-WmiObject -Namespace root\subscription -Class __EventFilter   | Select Name, Query
Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Select Name, CommandLineTemplate, ScriptText
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
Startup Folders + UserInit / AppInit_DLLsPowerShellGet-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Recurse
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Userinit, Shell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs -ErrorAction SilentlyContinue
Network + process correlation (catch C2 / backdoors)PowerShellGet-NetTCPConnection -State Established,Listen | Select LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Join-Object -Right (Get-Process) -On OwningProcess -Property Id,ProcessName,Path
# Or classic
netstat -ano | findstr "ESTABLISHED LISTENING"
PowerShell profiles (stealth logon script)PowerShell$PROFILE | fl *
Get-Content $PROFILE -ErrorAction SilentlyContinue
# All profiles
Get-ChildItem "$env:ProgramFiles\WindowsPowerShell\Modules", "$env:USERPROFILE\Documents\WindowsPowerShell" -Recurse -Include profile.ps1 -ErrorAction SilentlyContinue
Quick one-liner suspicious process huntPowerShellGet-Process | Where Path -notlike "*\Windows\*" -and Path -notlike "*\Program Files*" | Select Name, Id, Path, Company, Description | Sort Path
Linux – Top Persistence Hunting Commands
Systemd everywhere (most modern distros)Bashsystemctl list-unit-files --type=service | grep enabled
systemctl list-units    --type=service --state=running
# Suspicious custom units
find /etc/systemd /usr/lib/systemd -type f -name "*.service" -o -name "*.timer" 2>/dev/null | xargs grep -Ei "ExecStart|ExecStop|WorkingDirectory|User|Group"
systemctl list-timers --all
Cron / at / anacron (classic & still everywhere)Bashcrontab -l -u root; for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u $u 2>/dev/null; done
ls -la /etc/cron* /var/spool/cron/crontabs/ /var/spool/anacron/
cat /etc/crontab /etc/anacrontab
find /etc/cron.* -type f -exec cat {} +
Shell profiles & rc files (logon / sudo persistence)Bashgrep -rE "wget|curl|nc|bash -i|python -c|perl -e|sh -i" /etc/profile /etc/profile.d/ ~/.bash* ~/.zsh* ~/.profile /etc/bash.bashrc /etc/zsh/zprofile 2>/dev/null
cat ~/.bashrc ~/.bash_profile ~/.zshrc /etc/skel/.bashrc
SSH authorized_keys (backdoor accounts)Bashfind /home /root -name authorized_keys -exec grep -H "ssh-rsa\|ecdsa\|ed25519" {} \; 2>/dev/null
awk -F: '$3 >= 1000 {print $1,$6}' /etc/passwd | while read u h; do [ -f "$h/.ssh/authorized_keys" ] && echo "$u -> $h/.ssh/authorized_keys"; done
PAM & sudoers (privilege abuse)Bashgrep -rEi "session.*required|optional" /etc/pam.d/ /etc/pam.conf
visudo -c -f /etc/sudoers; find /etc/sudoers.d -type f -exec cat {} +
Kernel modules & LD_PRELOAD (rootkit level)Bashlsmod | grep -v "^Module"
cat /etc/ld.so.preload 2>/dev/null
find /lib /usr/lib -name "*.so" -mtime -7 2>/dev/null   # recent .so files
Boot & init persistenceBashcat /etc/rc.local /etc/init.d/* /etc/xdg/autostart/* 2>/dev/null
systemctl get-default   # graphical vs multi-user
cat /boot/grub/grub.cfg | grep -i linux   # look for init= or weird params
Quick suspicious binary / network huntBashnetstat -tulpn 2>/dev/null || ss -tulpn
lsof -i -P -n | grep ESTABLISHED
ps auxf | grep -E "nc|netcat|bash -i|python -c|perl|sh -c"
find /tmp /var/tmp /dev/shm -type f -executable -mtime -3 2>/dev/null
Fast Workflow Summary (no fluff)
Windows (5–10 min sweep)
Autoruns (GUI) → first
Run keys + services + scheduled tasks (PowerShell)
WMI subscriptions
Netstat / Get-NetTCPConnection + process correlation
Linux (5–10 min sweep)
systemd services/timers
All cron variants + /etc/crontab
Shell profiles + .ssh/authorized_keys
netstat/ss + ps auxf + recent executables in /tmp /dev/shm
Run these as root/admin. Pipe to | grep -iE "suspicious|http|tcp|127|169|curl|wget|nc|bash|python"
