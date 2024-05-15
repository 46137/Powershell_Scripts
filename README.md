# Powershell Scripts

This collection of scripts are being developed to aid a cyber analyst in host/network enumeration and investigation of a live network.

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

### **Powershell_One-Liners Tasks:**
- Commands for recyclebin,prefetch (include hashes).
  - Recycle bin command to get files from all users (SIDS), hash bin files?
- Alternate data streams.
- Add section for get-mail (mailserver).
- Network shares ADMIN$, IPC$, c$

# Table of Contents
- [Powershell Overview](#powershell-overview)
- [System Information](#system-information)




### **Powershell Overview**
```
Update-Help
Get-Help process #searching for commandlets
Get-Command *process #shows command types of the search
(Measure-Command{Get-ComputerInfo}).TotalSeconds #show how long it takes to run a command    
(Get-Host).version #lists the powershell version
```
### **System Information**