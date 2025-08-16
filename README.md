# Windows System Administration Reference

My personal Windows system administration reference

# Table of Contents

- [Table of Contents](#table-of-contents)
- [Resources](#resources)
- [Misc](#misc)
- [Graphical System Utilities](#graphical-system-utilities)
- [PowerShell](#powershell)
- [System32 / Command Prompt](#system32--command-prompt)
- [External Utilities](#external-utilities)
  - [Sysinternals](#sysinternals)

# Resources

- Windows documentation: <https://learn.microsoft.com/en-us/windows>

# Misc

- Common types of unmovable files are the paging file, hibernation file, and system restore points

# Graphical System Utilities

Note: The `.msc` extension is only required if launching via the Run menu

- Computer Management (`compmgmt.msc`)
- Event Viewer (`eventvwr`)
- Registry Editor (`regedit`)
- Disk Management (`diskmgmt.msc`)
- Windows Defender Firewall with Advanced Security (`wf.msc`)
- Control Panel (`control`)
  - Programs (`appwiz.cpl`)
- System Configuration (`msconfig`) (*Provides some limited configuration options, including boot options*)
- System Information (`msinfo32`)
- Windows Installer (`msiexec`)

# PowerShell

*PowerShell is a cross-platform task automation solution made up of a command-line shell, a scripting language, and a configuration management framework. PowerShell runs on Windows, Linux, and macOS.*

- Windows PowerShell Reference: <https://learn.microsoft.com/en-us/powershell/>
  - Module Browser: <https://learn.microsoft.com/en-us/powershell/module>

## Misc

- `Select-String` (`sls`) (*Finds text in strings and files*)

## Help / Basic Awareness

- Help
  - `Get-Help` (`help`) (*Displays help about Windows PowerShell cmdlets and concepts*)
    - `Get-Help <command>` to show the name, syntax, aliases, and remarks for the command
  - `<command> -?` to get help with the command (same output as `Get-Help`)
- Commands
  - `Get-Command` (`gcm`) (*Gets all commands*)
    - Default command information: CommandType, Name, Version, Source
    - `Get-Command` to list all available PowerShell commands and their information
    - `Get-Command -CommandType Application` to list all available applications (external executables) in the path and their information
    - `Get-Command -Module <module>` to show all commands available from the module and their information
    - `Get-Command <command>` to show the command's information
- Modules
  - `Get-Module` (`gmo`) (*Lists the modules imported in the current session or that can be imported from the PSModulePath*)
    - Default module information: ModuleType, Version, Name, ExportedCommands
    - `Get-Module` to list PowerShell modules loaded in the current session (modules are loaded on first use)
    - `Get-Module -ListAvailable` to list all available PowerShell modules
    - `Get-Module <module>` to list information for the module
- Formatting output
  - `Select-Object` (`select`) (*Selects objects or object properties*)
    - `<command> | Select-Object *` to list all objects provided from the command instead of the default view
  - `Format-List` (`fl`) (*Displays formatted text of the output as a list of properties*)
    - `<command> | Format-List *` to list all objects provided from the command instead of the default view, in text format (loses object orientation)
      - Eg: `Get-Module <module> | Format-List *` to view all information provided by the output of `Get-Module <module>` instead of the default set of information

## Process Management

- `Get-Process` (`ps`) (*Gets the processes that are running on the local computer*)
  - `Get-Process` to see all processes
  - `Get-Process <name>` to view the process

## Networking

### Firewall

- `Get-NetFirewallRule` (*Retrieves firewall rules from the target computer*)
  - `Get-NetFirewallRule` to get all firewall rules
    - Filters
      - `-Direction <Inbound|Outbound>`
      - `-Action <NotConfigured|Allow|Block>`
      - `-DisplayName <name>`
- `Set-NetFirewallRule` (*Modifies existing firewall rules*)
  - `Set-NetFirewallRule -Name "FPS-ICMP4-ERQ-In" -Enabled <True|False>` to enable/disable ICMPv4 pings

# System32 / Command Prompt

Command Prompt reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands

## Command Prompt

- `doskey` (*Edits command lines, recalls Windows commands, and creates macros*)
  - `doskey /history` to see command history
- `<command> >nul 2>&1` to redirect `stdout` and `stderr` to `nul`
- `echo %ERRORLEVEL%`
- `if errorlevel 1 echo ERROR` to print `ERROR` if the last `%ERRORLEVEL%`>=`1`

## General

- `help <command>` (*Provides help information for Windows commands*)
- `findstr` (*Searches for patterns of text in files*)
  - `/i` for case insensitive
  - `/v` to invert matches
  - `/m` to only list files with matches
- `tar` (*Manipulates archive files*; since `10.0.17063`)
  - `tar --help`
- `curl` (since `10.0.17063`)
  - `curl --help`

## Deprecated

- `wmic` (Windows Management Instrumentation Command-line; **deprecated since `10.0.19043`**)

## Starting Processes

- `start` (*Starts a separate Command Prompt window to run a specified program or command*)
  - `start "<title>" <program>`
  - `"<title>"` (required) to set the new Command Prompt window title
  - `/wait` to block parent batch program until finished
- `call` (*Calls one batch program from another without stopping the parent batch program*)
  - `call <program>`
- `cmd` (*Starts a new instance of the command interpreter, cmd.exe*)
  - `cmd <program>` (or just `<program>`) to pass on control to `<program>` and not return to script
  - `cmd /c <program>` (*Carries out the command specified by <string> and then exits the command processor*)
  - `cmd /k <program>` (*Carries out the command specified by <string> and keeps the command processor running*)

## Account Management

- `whoami` (*Shows information about the user, groups, and privileges for the account currently logged on to the local system*)
  - `whoami` to show `domain\username`
  - `whoami /all` to show information on the user, their groups, privileges, security IDs, and more
  - `whoami /priv` to show the security privileges of the current user
  - `whoami /groups` to show the group memberships of the current user
- `net` to perform operations on groups, users, account policies, shares, and more
  - `net session` to determine who's using resources on local computer
  - `net user` (*Details, adds, modifies, or deletes user accounts*)
    - `net user <username>` to see details of the user

## Networking

### Network Observability and Troubleshooting

- `tracert` (*Traces the route to a destination*)
- `pathping` (*Traces the route to a destination and calculates latency and loss between hops*)
- `netstat` (*Displays active network connections and statistics*)
  - `netstat 1` to run and refresh every 1 second
  - `netstat -bao` to display all active/listening TCP and UDP connections/ports (`-a`), display executable names (`-b`), and display PIDs (`-o`)
  - `netstat -r` to display routing table
  - `netstat -e` to display Ethernet statistics

### Network Management

- `ipconfig` (*Displays network configuration and refreshes DHCP and DNS settings*)
  - `/release` (*Releases the IPv4 address for the specified adapter*)
  - `/renew` (*Renews the IPv4 address for the specified adapter*)
  - `/flushdns` (*Purges the DNS Resolver cache*)
  - `/registerdns` (*Refreshes all DHCP leases and re-registers DNS names*)
- `netsh` (Network shell; *Displays and modifies network settings, automates tasks, and troubleshoots network issues locally or remotely*)
  - Note: The netsh docs are very helpful: <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh>
  - `netsh` to start an interactive netsh session
  - Wireless network information
  - `netsh wlan show all` to show all wireless device and networks information
  - Profiles
    - `netsh wlan show profiles`
    - `netsh wlan show profile "<profile-name>"`
    - `key=clear` to display security key in plaintext
  - Firewall
    - `netsh advfirewall show allprofiles` to show all firewall profiles
    - `netsh advfirewall firewall show rule name=all` to show all firewall rules
    - `netsh advfirewall firewall add rule name="<firewall-rule-name>" action=allow localport=8080 protocol=TCP dir=in` to add a firewall rule to allow inbound TCP traffic to port 8080 on the local host
    - `netsh advfirewall firewall show rule name="<firewall-rule-name>"` to show the firewall rule details
    - `netsh advfirewall firewall delete rule name="<firewall-rule-name>"` to delete the firewall rule
  - Port forwarding
    - `netsh interface portproxy add v4tov4 listenaddress=<src-address> listenport=<src-port> connectaddress=<dst-address> connectport=<dst-port>` to add a persistent TCP ipv4-to-ipv4 `portproxy` rule to forward traffic received from local `<src-address>: <src-port>` to `<dst-address>:<dst-port>`

## System Management

### Misc

- `sc` (*Interface to Service Control Manager and services*)

### System Information

- `ver` (*Displays the Windows version*)
- `systeminfo` (*Displays operating system configuration information for a local or remote machine, including service pack levels*)

### Disk Management

- `diskpart` (*Manages disks, partitions, volumes, and virtual hard disks*; interactive)
- `fsutil` (*Performs tasks related to FAT and NTFS file systems, such as managing reparse points, handling sparse files, or dismounting a volume*)
- `sfc` (*Scans the integrity of all protected system files and replaces incorrect versions with correct Microsoft versions*)
  - `/scannow` to perform the scan on all files and repair
    - `/scanfile <file>` to perform only on the file
  - `/verifyonly` to perform the scan on all files but not repair
    - `/verifyfile <file>` to perform only on the file
  - Offline
    - `/offwindir <offline-windows-dir>` to perform the scan and repairs on an offline Windows directory
    - `/offbootdir <offline-boot-dir>` to perform the scan and repairs on an offline boot directory
    - `/offlogfile=<file>` to specify log file for offline scan and repairs
- `defrag`
  - **NOTE!** Do not use the traditional defragmentation option with SSDs, which is **default**. Use with `/o` (see below) instead.
  - `defrag c: /a /u /v` to perform an fragmentation analysis only (`/a`) on C:, print progress (`/u`), and use verbose output (`/v`)
  - `/o` (*Perform the proper optimization for each media type*)

### Registry

- `reg` (*Performs operations on registry subkey information and values in registry entries*; **NOTE!** Use with caution: This can break your system)
  - Query
    - `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"` to query personalization registry subkeys
    - `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme` to query `AppsUseLightTheme` registry entry
  - Add/modify
    - `reg add <keyname> /v <valuename> /t <data-type> /d <data> /f` to add/modify registry entry values (`/f` to overwrite existing entry)

### Environment Variables

- `setx` (*Creates or modifies environment variables in the user or system environment. Can set variables based on arguments, regkeys or file input.*)
- `set` (*Displays, sets, or removes cmd.exe environment variables*)
  - Update system path:
  ```batch
  set "NEW_PATH=%PATH%;C:\new\dir"
  setx /M PATH "%NEW_PATH%"
  ```

## Process Management

- `tasklist` (*Displays a list of currently running processes on the local computer or on a remote computer*)
  - `tasklist` to see the tasklist
    - Default task information: Image Name, PID, Session Name, Session#, Mem Usage
  - `tasklist /v` to see the verbose tasklist
    - Verbose task information: Image Name, PID, Session Name, Session#, Mem Usage, Status, User Name, CPU Time, Window Title
  - `tasklist /fi "imagename eq procexp*"` to filter processes for Process Explorer
- `taskkill` (*Ends one or more tasks or processes*)
  - Examples
    - `taskkill /im procexp*` to filter for and kill Process Explorer
    - `taskkill /pid <pid>` to filter for and kill the process by PID
  - Parameters
    - `/im <imagename>`
    - `/pid <pid>` to kill by PID
    - `/fi <filter>`
    - `/f` to kill forcefully
    - `/t` to kill child processes along with parent

## Package Management (Winget)

`winget` comes pre-installed as the default package manager since `10.0.17763`

Winget documentation: <https://learn.microsoft.com/en-us/windows/package-manager/winget>

---

- `winget list` to list installed packages
- `winget search <command>` to search for package candidates
- `winget show <package>` to show details of package candidates
- `winget install <package>` to install a package
  - `--accept-package-agreements` to accept any license agreements, and avoid the prompt
  - `--accept-source-agreements` to accept any source license agreements, and avoid the prompt

## Tasks

- Switch system to dark mode (`reg`, `taskkill`)
  - `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f` to switch system theme to dark mode
  - `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 0 /f` to switch apps to dark mode
  - `taskkill /f /im explorer.exe && start explorer.exe` to restart Explorer, which refreshes the desktop and applies the dark theme

# External Utilities

## Sysinternals

- See the Sysinternals page: <https://learn.microsoft.com/en-us/sysinternals>
- See the list of tools: <https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite>

### Graphical

- Process Explorer
- Process Monitor
- TCPView (*Shows detailed listings of all TCP and UDP endpoints*)
- Autoruns (*Shows the configured auto-start applications*)
- DiskView (*Shows a graphical map of the disk*)

### Command-line

- `autorunsc` (Command-line version of Autoruns)
- `sigcheck` (*Shows file information including signature details and performs optional VirusTotal scan*)
- `listdlls` (*Reports DLLs loaded into processes*)
- `contig` (*Performs single-file defragmentation*)
- `strings`
- `psloglist` (*Dumps the contents of an Event Log on the local or a remote computer*)
- `tcpvcon` (Command-line version of TCPView)
  - `-a` to show all endpoints
  - `-n` to not resolve addresses

