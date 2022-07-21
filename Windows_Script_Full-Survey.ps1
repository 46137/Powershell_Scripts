function Get-FullSurvey(){
    $ErrorActionPreference = 'SilentlyContinue' # Disables errors. Errors will occur depending on it being a workstation or a AD, change to 'Continue' to see errors.
    <#
    .SYNOPSIS
    Tasks:
    Get-UserGroups (adusers,adgroups,adgroupadmins,countfailedlogonperuser)
    get-art (hostsfile,run,tempfiles,tempfilesauth,usb)
    get-events 
    .DESCRIPTION
    Setup:
    Import-Module .\Windows_Script_Full-Survey.ps1 -Force

    Some commands will have two versions:
        raw command will end in r
        filtered command will end in f
    
    .EXAMPLE
    Running the script to list all the categories:
    Get-FullSurvey
    
    Running the script for a category:
    (Get-FullSurvey).sysinfo

    Running the script for a sub-category:
    (Get-FullSurvey).sysinfo.installedapps64 |ft

    Running the script into a variable for static analysis:
    $fullsurvey = Get-FullSurvey
    $fullsurvey.sysinfo.timezone
    #>
    function Get-SysInfo(){
        $datetime = [System.DateTime]::now
        $timezone = [System.TimeZoneInfo]::Local
        $osinfo = Get-WmiObject -Class Win32_OperatingSystem |Select-Object -Property Caption, Version, CSName, OSArchitecture, WindowsDirectory
        $adinfo = Get-ADDomain
        $apps32 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending 
        $apps64 = Get-ItemProperty HKLM:\software\microsoft\windows\currentversion\Uninstall\* |Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending 

        # Creates an empty hashtable.
        $return_data = @{}
        # Adding the collected data to the hashtable.
        $return_data.Add("DateTime", $datetime)
        $return_data.Add("TimeZone", $timezone)
        $return_data.Add("OSInfo", $osinfo)
        $return_data.Add("ADInfo", $adinfo)
        $return_data.Add("InstalledApps32", $apps32)
        $return_data.Add("InstalledApps64", $apps64)
        # Returns the hashtable.
        return $return_data
    }
    
    function Get-UserGroups(){
        $accounts = Get-WmiObject -Class win32_useraccount |Select-Object -Property AccountType,Name,FullName,Domain,SID
        $lg = Get-LocalGroup
        $la = Get-LocalGroupMember -Group Administrators |Select-Object -Property ObjectClass, Name, PrincipalSource, SID
        function Get-LastLogon {

            [CmdletBinding()]
            param()
            #Raw data.
            $UserAccounts_Raw = Get-WmiObject -Class win32_useraccount
            $UserProfiles_Raw = Get-WmiObject -Class win32_userprofile
            
            # Creates an array outside the loop to input the new objects into later.
            $UsersInfo = @()
            #Starts a loop that will go through each profile one by one.
            foreach ($Profile in $UserProfiles_Raw){ 
                #Starts a loop that will go through each account one by one.
                foreach ($Account in $UserAccounts_Raw){
                    #Compares the SID's of the first profile and account selected. If they are the same a new object is created comprising on information from both the user's profile and account.
                    if ($Account.SID -match $Profile.SID){
                        $UserInfo = New-Object -TypeName PSObject |Select-Object -Property LastUseTime,Name,FullName,Domain,AccountType,LocalPath,SID,Description
                        $UserInfo.Name = $Account.Name
                        # '[System.Management.ManagementDateTimeConverter]::ToDateTime' this converts the 'LastUseTime' into a more human readable format.
                        $UserInfo.LastUseTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($Profile.LastUseTime)
                        $UserInfo.FullName = $Account.FullName
                        $UserInfo.AccountType = $Account.AccountType
                        $UserInfo.Domain = $Account.Domain
                        $UserInfo.LocalPath = $profile.localpath
                        $UserInfo.SID = $Account.SID
                        $UserInfo.Description = $Account.Description
                        #Adds each new object into the array.
                        $UsersInfo += $UserInfo
                    }
                }
            } 
            $UsersInfo
        }
        $lastlogon = Get-LastLogon

        # Creates an empty hashtable.
        $return_data = @{}
        # Adding the collected data to the hashtable.
        $return_data.Add("UserAccounts", $accounts)
        $return_data.Add("LocalGroups", $lg)
        $return_data.Add("LocalAdmins", $la)
        $return_data.Add("UserLastLogon", $lastlogon)
        # Returns the hashtable.
        return $return_data
    }
    function Get-NetInfo(){
        $ipr = Get-NetIPConfiguration -Detailed
        $ipf = Get-NetIPConfiguration |Select-Object -Property InterfaceAlias,IPv4Address,IPv4DefaultGateway
        $ipa = Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"} |Select-Object -Property InterfaceAlias,IPv4Address,IPv4DefaultGateway
        $nsr = Get-NetTCPConnection 
        $nsf = Get-NetTCPConnection |Where-Object {$_.state -match "listen" -or $_.state -match "establish" -and $_.LocalAddress -ne "0.0.0.0" -and $_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::" -and $_.LocalAddress -ne "::1"} |Select-Object -Property CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, AppliedSetting, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |Sort-Object -Property CreationTime -Descending |Format-Table
        $pr = Get-Process
        $pf = Get-WmiObject -Class Win32_Process |Select-Object ProcessId, ParentProcessId, Name, ExecutablePath
        $prec = Get-WmiObject -Class win32_process |ForEach-Object {New-Object -Type PSCustomObject -Property @{'CreationDate' = $_.converttodatetime($_.creationdate); 'PID' = $_.ProcessID; 'PPID' = $_.ParentProcessID; 'Name' = $_.Name; 'Path' = $_.ExecutablePath}} |Select-Object -Property CreationDate, PID, PPID, Name, Path |Sort-Object -Property CreationDate -Descending
        $pw = Get-Process |Where-Object {$_.mainWindowTitle} |Select-Object -Property Id,ProcessName,MainWindowTitle


        # Creates an empty hashtable.
        $return_data = @{}
        # Adding the collected data to the hashtable.
        $return_data.Add("IPInfoR", $ipr)
        $return_data.Add("IPInfoF", $ipf)
        $return_data.Add("IPInfoA", $ipa)
        $return_data.Add("ConnectionR", $nsr)
        $return_data.Add("ConnectionF", $nsf)
        $return_data.Add("ProcessR", $pr)
        $return_data.Add("ProcessF", $pf)
        $return_data.Add("ProcessRecent", $prec)
        $return_data.Add("ProcessWindow", $pw)

        # Returns the hashtable.
        return $return_data
    }

    function Get-ServiceTask(){
        $serr = Get-Service |Sort-Object -Property Status -Descending
        $serf = Get-WmiObject -Class Win32_Service |Select-Object -Property ProcessId, Name, StartMode, State, PathName |Sort-Object -Property State
        $taskr = Get-ScheduledTask
        $taskc = Get-ScheduledTask |Select-Object -Property Date,State,TaskName,TaskPath |Sort-Object -Property Date -Descending
        $taskrun = Get-ScheduledTask -TaskName * |Get-ScheduledTaskInfo |Select-Object -Property LastRunTime, TaskName, TaskPath |Sort-Object -Property LastRunTime -Descending

        # Creates an empty hashtable.
        $return_data = @{}
        # Adding the collected data to the hashtable.
        $return_data.Add("ServiceF", $serf)
        $return_data.Add("ServiceR", $serr)
        $return_data.Add("TaskR", $taskr)
        $return_data.Add("TaskCreated", $taskc)
        $return_data.Add("TaskRun", $taskrun)


        # Returns the hashtable.
        return $return_data
    }

    # Creates an empty hashtable for the overall results.
    $results = @{}
    # Adding the sub-functions to the hashtable.
    $sysinfo = Get-SysInfo
    $results.Add("SysInfo", $sysinfo)
    $usergroups = Get-UserGroups
    $results.Add("UserGroups", $usergroups)
    $net = Get-NetInfo
    $results.Add("NetInfo", $net)
    $st = Get-ServiceTask
    $results.Add("ServiceTask", $st)
    # Returns the hashtable.
    return $results    
}
Get-FullSurvey