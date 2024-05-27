# POWERSHELL

This collection of commands & scripts are being developed to aid a cyber analyst in host/network enumeration and investigation of a live network. The readme.md below contains short commands that can be used for quick analysis.

# Commands Table of Contents
- [Powershell Overview](#powershell-overview)
- [Scanning](#scanning)
- [Remoting](#remoting)
  - [WinRM](#winrm)
  - [WMIC](#wmic)
  - [PSexec.exe](#psexecexe)
  - [Runas.exe](#runasexe)
  - [RDP](#rdp)
- [Running Scripts](#running-scripts)
- [System Information](#system-information)
- [Host Enumeration Tasks](#host-enumeration-tasks)
- [Modules Framework Tasks](#modules-framework-tasks)
- [Readme.md Tasks](#readmemd-tasks)

### **Powershell Overview**
### __Powershell Overview__
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
(Measure-Command{[COMMAND]}).TotalSeconds
```

### **Scanning**
```powershell
#Slow ping sweep.
1..254 | ForEach-Object { Test-Connection -count 1 127.0.0.$_ -ErrorAction SilentlyContinue}
```
```powershell
#Fast ping sweep.
$Subnets = '10.10.10'#,'10.10.11'
#Creates an array of active hosts via ICMP.
$Up_Hosts = @()
foreach ($Subnet in $Subnets){
    $IPs = 1..254 | ForEach-Object {"$($Subnet).$_"}
    $Ping = $IPs|ForEach-Object {
        #(New-Object Net.NetworkInformation.Ping).SendPingAsync($_,250) 
        [Net.NetworkInformation.Ping]::New().SendPingAsync($_, 250) #PowerShell v5
    }
    [Threading.Tasks.Task]::WaitAll($Ping)
    $Ping.Result | ForEach-Object {
        if($_.Status -eq 'Success'){
            $Up_Hosts += $_.Address.IPAddressToString
            $IP = $_.Address.IPAddressToString
            "$IP - Hosts Up"
        }
    }
}
$Up_Hosts
```
```powershell
#Enabling ping on Win10 which could have it disabled by default.
New-NetFirewallRule -DisplayName "Allow Ping" -Direction Inbound -Protocol ICMPv4 -Action Allow -Enabled True -Profile Any -LocalPort Any -EdgeTraversalPolicy Allow
#Enabling ping on Win7 which could have it disabled by default.
netsh firewall set icmpsetting 8
```
```powershell
#Slow port test. Common ports: 135(Domain),445(SMB),5985/6(WinRM),22(SSH),3389(RDP)
Test-NetConnection -Port [PORT] -ComputerName [IP ADDRESS]
```
```powershell
#Fast port test.
New-Object System.Net.Sockets.TcpClient -ArgumentList [IP ADDRESS],[PORT]
```
```powershell
#Fast port scan.
$Subnets = "10.10.10."#,"10.10.11."
$IPs = 1..255
$Port = 135 #Common ports: 135(Domain),445(SMB),5985/6(WinRM),22(SSH),3389(RDP)
$TimeoutMilliseconds = 50
#Creates an array of active hosts.
$Open_Port = @()
foreach ($Subnet in $Subnets){
    $IPs | ForEach-Object{
        $IP = $Subnet + $_
        $Socket = [System.Net.Sockets.TcpClient]::new()
        $Result = $Socket.BeginConnect($IP, $Port, $null, $null) # Null 1 is optional callback methods, null 2 is operation state for callback method.
        $Success = $Result.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)
            if ($Success -and $Socket.Connected){
                $Open_Port += $IP
                "$IP - Open Port: $Port"
                $Socket.Close()
            }
        Write-Progress -Activity "Scanning Network" -Status "$Subnet$_" -PercentComplete (($_/($IPs.Count))*100) # Progress bar.
    }
}
```

### **Remoting**
### WinRM
```powershell
#Tests if the WinRM service is running on that endpoint.
Test-WSMan -ComputerName [NAME\IP]
```
```powershell
#Needs to be enabled on the endpoint before trying to remote to it.
Enable-PSRemoting -Force
```
```powershell
#Checking current localhost configuration.
Get-Item WSMan:\localhost\client\trustedhosts
#Modify localhost to allow a connection to a specific subnet.
Set-Item WSMan:\localhost\client\trustedhosts "172.15.2.*"
#Modify localhost to allow a connection to all endpoints.
Set-Item WSMan:\localhost\client\trustedhosts
```
```powershell
#Opening port 5985 on endpoint if 'Enable-PsRemoting' doesn't work.
New-NetFirewallRule -DisplayName "Allow WinRM Port 5985" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow
```
```powershell
#Starting a new local or domain session. Using a IP Address will use NTLM authentication & Computer Name will use Kerberos authentication.
New-PSSession -ComputerName [NAME\IP] -Credential [DOMAIN\USER]
#Shows active sessions.
Get-PSSession
#Entering session
Enter-PSSession [NUMBER]
#Removing all sessions. 
Get-PSSession |Remove-PSSession
```
```powershell
#Running a local script on a remote endpoint.
Invoke-Command -ComputerName [NAME\IP] -Credential [DOMAIN\USER] -FilePath C:\windows\file.ps1
```
```powershell
#Running a command on a remote endpoint.
Invoke-Command -ComputerName [NAME\IP] -Credential [DOMAIN\USER] -ScriptBlock {[COMMAND]}
```
```powershell
#Running a command on a remote endpoint with esablished credentials.
$User = [DOMAIN\USER]
$PWord = Get-Content [PATH\TO\SECURE\FILE] | ConvertTo-SecureString
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
Invoke-Command -ComputerName [NAME\IP] -Credential $Credential -ErrorAction SilentlyContinue -ScriptBlock {[COMMAND]}
```
```powershell
#Moving & removing files in a session.
#Create session.
$Session = New-PSSession [NAME\IP] -Credential [DOMAIN\USER]
#Copy local file to remote endpoint.
Copy-Item -Path [LOCAL\FILE\PATH] -ToSession $Session -Destination [REMOTE\FILE\PATH]
#Removing file on remote endpoint.
Invoke-Command -Session $Session -ScriptBlock{Remove-Item -Path [PATH\TO\FILE] -Recurse -Force}
#Copy remote file to local host.
Copy-Item -Path [REMOTE\FILE\PATH] -Destination [LOCAL\FILE\PATH] -FromSession $Session
```

### WMIC
WMIC commands use DCOM over port 135 to communicate with remote endpoints.
```powershell
#Displays hostname of the remote endpoint. (May need authentication)
wmic /NODE:[NAME\IP] ComputerSystem GET Name
```
```powershell
#Displays OS name.
wmic /NODE:[NAME\IP] /USER:[DOMAIN\USER] OS GET Name
```
```powershell
#Starting a service.
wmic /NODE:[NAME\IP] /USER:[DOMAIN\USER] Service where caption="Windows Remote Management (WS-Management)" call startservice
```
```powershell
#Enabling PSRemoting.
wmic /NODE:[NAME\IP] /USER:[DOMAIN\USER] process call create "powershell.exe -NoProfile -Command Enable-PSRemoting -Force"
```

### PSexec.exe
```powershell
#Opening powershell on a remote endpoint. (May need authentication)
psexec.exe \\[NAME\IP] powershell.exe
```
```powershell
#Enabling PSRemoting.
psexec.exe \\[NAME\IP] -u [DOMAIN\USER] -p [PASSWORD] -h -s powershell.exe Enable-PSRemoting -Force
```

### Runas.exe
```powershell
#Starting a powershell or cmd session.
runas /noprofile /user:dwc\ubolt powershell
```

### RDP
```powershell
#Blocking RDP firewall rule.
New-NetFirewallRule -DisplayName "Block RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block
#Removing RDP block rule.
Remove-NetFirewallRule -DisplayName "Block RDP"
```

### **Running Scripts**
```powershell
#Shows the current state of the policies of the endpoint.
Get-ExecutionPolicy -List
#Setting to 'RemoteSigned' where downloaded scripts must be signed by a trusted publisher. (May need elevated privileges)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
```
```powershell
#Creating a new powershell session to bypass the need for elevated privileges.
Powershell.exe -ExecutionPolicy Bypass
#Creating a new powershell version 2 session to bypass language mode.
Powershell.exe -Version 2 -ExecutionPolicy Bypass
```
```powershell
#Shows the current language mode state. ConstrainedLanguage constrains the use of certain features, NoLanguage disables all.
$ExecutionContext.SessionState.LanguageMode
#Changing language mode for that powershell session.
$ExecutionContext.SessionState.LanguageMode = "FullLanguage"
```
```powershell
#Generates a secure password file to be used in scripts credentials. 
Read-Host -AsSecureString |ConvertFrom-SecureString |Out-File [OUTPUT\FILE\LOCATION]
```

### **System Information**

### **Host Enumeration Tasks**
- Rework 'Payload_KeyTerrain-Survey'.
- Decide if to complete 'Manual_Full-Survey'.
- Create 'Auto CIM-OS-Detection'?

### **Modules Framework Tasks**
- Find a better way in 'Auto_Invoke-Modules' to call modules (not via a txt file).
- Complete 'BT-Persistence' module.
- Complete 'BT-PII' module.
- Complete 'Payload_KeyTerrain-Survey-Modules'.
- Create 'BT-ADServer' module.
- Create 'BT-MailServer' module.
- Create 'BT-WebServer' module.
- Create 'BT-RDSHashes' module?

### **Readme.md Tasks**
```powershell

```
- Commands for recyclebin,prefetch (include hashes).
  - Recycle bin command to get files from all users (SIDS), hash bin files?
- Alternate data streams.
- Add section for get-mail (mailserver).
- Network shares ADMIN$, IPC$, c$