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

        # Create an empty hashtable.
        $return_data = @{}
        # Add the collected data to the hashtable.
        $return_data.add("DateTime", $datetime)
        $return_data.add("TimeZone", $timezone)

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