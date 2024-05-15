# Powershell Scripts

This collection of scripts are being developed to aid a cyber analyst in host/network enumeration and investigation of a live network. The readme.md below contains single commands that can be used for quick analysis.

# Commands Table of Contents
- [Powershell Overview](#powershell-overview)
- [Scanning](#scanning)
- [System Information](#system-information)
- [Ongoing Tasks](#readmemd-tasks)


### **Powershell Overview**
```powershell
#Updating
Update-Help

#Searching for commandlets.
Get-Help process

#Shows command types of the search.
Get-Command *process

#Lists the powershell version.
(Get-Host).version

#Show how long it takes to run a command.
(Measure-Command{Get-ComputerInfo}).TotalSeconds
```
### **Scanning**
**Slow ping sweep**
```powershell
#Slow ping sweep.
1..254 | ForEach-Object { Test-Connection -count 1 127.0.0.$_ -ErrorAction SilentlyContinue}
```
```powershell
Test-WSMan -ComputerName 172.16.12.10 #determines whether WinRM service is running on that endpoint
Test-NetConnection -Port 5985 -ComputerName 172.16.12.10 #tests if HTTP WinRM port related to WinRM are open on that endpoint, 5986 for HTTPS
New-Object System.Net.Sockets.TcpClient -ArgumentList 172.16.12.10,5985 #Quicker than Test-NetConnection
```
### **System Information**
### **Host Enumeration Tasks:**
- Rework 'Payload_KeyTerrain-Survey'.
- Decide if to complete 'Manual_Full-Survey'.
- Create 'Auto CIM-OS-Detection'?

### **Modules Framework Tasks:**
- Find a better way in 'Auto_Invoke-Modules' to call modules (not via a txt file).
- Complete 'BT-Persistence' module.
- Complete 'BT-PII' module.
- Complete 'Payload_KeyTerrain-Survey-Modules'.
- Create 'BT-ADServer' module.
- Create 'BT-MailServer' module.
- Create 'BT-WebServer' module.
- Create 'BT-RDSHashes' module?

### **Readme.md Tasks:**
```powershell

```
- Commands for recyclebin,prefetch (include hashes).
  - Recycle bin command to get files from all users (SIDS), hash bin files?
- Alternate data streams.
- Add section for get-mail (mailserver).
- Network shares ADMIN$, IPC$, c$