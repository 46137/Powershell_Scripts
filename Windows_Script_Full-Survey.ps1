function Get-FullSurvey(){
    <#
    .SYNOPSIS

    .DESCRIPTION
    Setup:
    Import-Module .\Windows_Script_Full-Survey.ps1 -Force
    
    .EXAMPLE
    (Get-FullSurvey).osinfo
    #>
    function Get-OSInfo(){
        $datetime = [System.DateTime]::now
        $timezone = [System.TimeZoneInfo]::Local
        $osinfo = Get-WmiObject -Class Win32_OperatingSystem |Select-Object -Property Caption, Version, CSName, OSArchitecture, WindowsDirectory
        $apps32 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending |Format-Table -Wrap
        $apps64 = Get-ItemProperty HKLM:\software\microsoft\windows\currentversion\Uninstall\* |Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending |Format-Table -Wrap

        # Create an empty hashtable.
        $return_data = @{}
        # Add the collected data to the hashtable.
        $return_data.Add("DateTime", $datetime)
        $return_data.Add("TimeZone", $timezone)
        $return_data.Add("OSInfo", $osinfo)
        $return_data.Add("InstalledApps32", $apps32)
        $return_data.Add("InstalledApps64", $apps64)

        # Return the hashtable.
        return $return_data
    }
    
    function Get-LocalUserInfo(){
        $usera = Get-WmiObject -Class win32_useraccount |Select-Object -Property AccountType,Name,FullName,Domain,SID |Format-Table -Wrap #finds detailed accounts
        $userp = Get-WmiObject -Class win32_userprofile |Select-Object -Property lastusetime,localpath,SID |Sort-Object lastusetime -Descending |Format-Table -Wrap #finds account lastusetime

        # Create an empty hashtable.
        $return_data = @{}
        # Add the collected data to the hashtable.
        $return_data.add("UserAccount", $usera)
        $return_data.add("UserProfile", $userp)
        
        # Return the hashtable.
        return $return_data
    }


    $results = @{}
    $osinfo = Get-OSInfo
    $results.Add("OSInfo", $osinfo)
    $localuserinfo = Get-LocalUserInfo
    $results.Add("LocalUserInfo", $localuserinfo)
    return $results    
}
Get-FullSurvey