function Get-UsersInfo {
    <#
    .SYNOPSIS
    Gets selected user information from both the Win32_UserAccount and Win32_UserProfile.  
      
    .DESCRIPTION
    To Run: Import-Module .\Get-UsersInfo.psm1 -Force
    Return an array of custom psobjects that include: Account_Name, Profile_LastUseTime, Account_Type, Account_FullName, Profile_LocalPath, Account_SID and Account_Description.
    Note: For Win10 use 'Get-LocalGroupMember -Group Users |Select-Object -Property ObjectClass, Name, PrincipalSource, SID'

    .EXAMPLE
    Get-UsersInfo
    #>
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
                $UserInfo = New-Object -TypeName PSObject |Select-Object -Property Account_Name,Profile_LastUseTime,Account_Type,Account_FullName,Profile_LocalPath,Account_SID,Account_Description
                $UserInfo.Account_Name = $Account.Caption
                # '[System.Management.ManagementDateTimeConverter]::ToDateTime' this converts the 'LastUseTime' into a more human readable format.
                $UserInfo.Profile_LastUseTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($Profile.LastUseTime)
                $UserInfo.Account_FullName = $Account.FullName
                $UserInfo.Account_Type = $Account.AccountType
                $UserInfo.Profile_LocalPath = $profile.localpath
                $UserInfo.Account_SID = $Account.SID
                $UserInfo.Account_Description = $Account.Description
                #Adds each new object into the array.
                $UsersInfo += $UserInfo
            }
        }
    } 
    $UsersInfo
}
