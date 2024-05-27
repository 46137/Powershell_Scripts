<h1 style="text-align: center;">POWERSHELL</h1>


This collection of commands & scripts are being developed to aid a cyber analyst in host/network enumeration and investigation of a live network. The readme.md below contains short commands that can be used for quick analysis.

# Commands Table of Contents
- [Powershell Overview](#powershell-overview)
- [Scanning](#scanning)
- [Remoting](#remoting)
  - [WinRM](#winrm)
  - WMIC
  - PSexec.exe
  - Runas.exe
- [System Information](#system-information)
- [Host Enumeration Tasks](#host-enumeration-tasks)
- [Modules Framework Tasks](#modules-framework-tasks)
- [Readme.md Tasks](#readmemd-tasks)

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
Test-WSMan -ComputerName [IP ADDRESS]
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
New-NetFirewallRule -DisplayName "Allow WinRM Port 5985" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow #Opening port 5985 on endpoint if 'Enable-PsRemoting' doesn't work.
New-PSSession -ComputerName 172.16.12.10 -Credential Administrator #This will start a session but keep you local (For credentials it can be local or domain)
Get-PSSession #Shows active sessions.
Enter-PSSession 8 
Get-PSSession |Remove-PSSession #Removes all sessions.

Invoke-Command -ComputerName 172.16.1.53 -Credential Administrator -FilePath C:\windows\file.ps1 #running a local script on a remote box
Invoke-Command -ComputerName 172.16.1.53 -Credential Administrator -ScriptBlock {Start-Process -FilePath 'C:\file.exe'} #running a file on the remote box
Invoke-Command -ComputerName 172.16.1.53 -Credential Administrator -ScriptBlock {Get-ChildItem C:\Users\Bob\Desktop} #viewing files on remote box
Invoke-Command -ComputerName 172.16.1.53 -Credential Administrator -ScriptBlock {Get-Content C:\Users\Bob\Desktop\Names.txt} #viewing contents of file on remote box

$session=New-PSSession -ComputerName 172.16.1.51 -Credential Administrator #create session and copy item from it to local box
Copy-Item -Path 'C:\winlog.msi' -ToSession $session -Destination 'C:\winlog.msi' #copy a file to that session
Invoke-Command -ComputerName 172.16.1.51 -Credential Administrator -ScriptBlock {Start-Process -FilePath 'C:\winlog.msi' Get-Service winlogbeat} #run that file and show if the service is up
```



**WMIC**
```powershell
    wmic #if winRM isn't enabled you can try and connect with wmic over port 135(RPC of TCP). Open terminal or cmd to enter a wmic prompt
    wmic /NODE:"172.16.12.10" computersystem get name #shows hostname of the endpoint
    wmic /NODE:"ServerName" /USER:"yourdomain\administrator" OS GET Name #shows OS name, can use as a test
    wmic /NODE:"ServerName" /USER:"yourdomain\administrator" service where caption="Windows Remote Management (WS-Management)" call startservice #starts service on a remote host

```
**PSexec.exe**
```powershell
    psexec.exe \\172.16.12.10 cmd #can also try this or hostname to connect over 135 & 445. 
    psexec.exe \\172.16.12.10 -h -s powershell.exe Enable-PSRemoting -Force
    psexec.exe \\172.16.12.10 -u "yourdomain\administrator" -p "password" -s C:\Windows\System32\winrm.cmd quickconfig -q  

```
**Runas.exe**
```powershell
runas /noprofile /user:dwc\ubolt cmd #testing opening cmd with credentials.

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