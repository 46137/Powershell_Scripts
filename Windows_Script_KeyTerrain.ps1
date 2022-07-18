#Script intent: If you're given keyterrain to monitor daily throughout an exercise, this will create a local output of each host to look for anomalies.

$hosts = 'WIN10-TEST','DESKTOP-9R76OA2' #List hosts or ips.
#read-host -assecurestring | convertfrom-securestring | out-file C:\Users\Heady\Desktop\secure.txt <- Run this command once to generate your secure password file. 
$User = "546CMT\Administrator"
$PWord = Get-Content 'C:\Users\Heady\Desktop\secure.txt' | ConvertTo-SecureString
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
$DTG = Get-Date -Format "yyMMdd"

foreach ($h in $hosts){

    $output = Invoke-Command -ComputerName $h -Credential $Credential -ScriptBlock { #list below the commands you want to query.

        [System.DateTime]::now
        [System.TimeZoneInfo]::Local
        "=== OS SUMMARY ==="
        Get-WmiObject -Class Win32_OperatingSystem |Select-Object -Property Caption, Version, CSName, OSArchitecture, WindowsDirectory #condensed OS information
        "=== ACTIVE INTERFACES ==="
        Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"} |Select-Object -Property InterfaceAlias,IPv4Address,IPv4DefaultGateway # better ipconfig, shows active interfaces.
        "=== RECENTLY INSTALLED APPLICATIONS ==="
        Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending|Select-Object -First 5 |Format-Table -AutoSize #lists 5 most recently installed 32bit programs
        Get-ItemProperty HKLM:\software\microsoft\windows\currentversion\Uninstall\* |Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending |Select-Object -First 5 |Format-Table -Wrap #lists 5 most recently installed 64bit programs
        "=== RECENTLY USED ACCOUNTS ==="
        Get-WmiObject -Class win32_userprofile |Select-Object -Property lastusetime,localpath,SID |Sort-Object lastusetime -Descending |Select-Object -First 5 |Format-Table -Wrap #finds account lastusetime
        "=== CONNECTIONS (ESTABLISHED/LISTEN) ==="
        Get-NetTCPConnection |Where-Object {$_.state -match "listen" -or $_.state -match "establish"} |Select-Object -Property CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |Format-Table #looking for established or listen & adds process
        "=== PROCESSES ==="
        Get-WmiObject -Class Win32_Process |Select-Object ProcessId, ParentProcessId, Name, ExecutablePath |Format-Table -Wrap #shows additional path and PPID
        "=== RUNNING SERVICES ==="
        Get-WmiObject -Class Win32_Service |Where-Object {$_.State -eq "Running"} |Select-Object -Property ProcessId, Name, StartMode, State, PathName |Sort-Object -Property State |Format-Table -Wrap #shows running services with path
        "=== RECENTLY CREATED TASKS ==="
        Get-ScheduledTask |Select-Object -Property Date,State,TaskName,TaskPath |Sort-Object -Property Date -Descending | Select-Object -First 20 |Format-Table -Wrap #recently created tasks
        "=== RECENTLY RUN TASKS ==="
        Get-ScheduledTask -TaskName * |Get-ScheduledTaskInfo |Select-Object -Property LastRunTime, TaskName, TaskPath |Sort-Object -Property LastRunTime -Descending |Format-Table -Wrap #recently run tasks
        "=== HOSTS FILE ==="
        Get-Content C:\Windows\System32\drivers\etc\hosts
        "=== REGISTRY RUNKEYS ==="
        Get-Item -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        Get-ItemProperty -path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        Get-Item -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        "=== TEMP FILES ==="
        Get-ChildItem -Path C:\Windows\Temp |Sort-Object -Property LastWriteTime -Descending |Format-Table LastWriteTime,CreationTime,Mode,Length,FullName #shows contents of folder
        Get-AuthenticodeSignature -FilePath C:\Windows\Temp\* |Where-Object {$_.Status -ne "Valid"} # Checks for files that aren't valid
        Get-ChildItem -Path C:\Users\Administrator\AppData\Local\Temp |Sort-Object -Property LastWriteTime -Descending |Format-Table LastWriteTime,CreationTime,Mode,Length,FullName #shows contents of folder
        Get-AuthenticodeSignature -FilePath C:\Users\Administrator\AppData\Local\Temp\* |Where-Object {$_.Status -ne "Valid"} # Checks for files that aren't valid 
        "=== NAMED PIPES ==="
        Get-ChildItem \\.\pipe\ |Sort-Object -Property LastWriteTime -Descending |Format-Table LastWriteTime,CreationTime,Mode,Length,FullName #shows named pipes
    
    }
    $output
    $output | Out-File -Append C:\Users\heady\Desktop\$DTG-$h-KeyTerrain.txt
    
}
