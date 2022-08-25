function BT-UserInfo {
    <#
    .SYNOPSIS
    Gets selected user information from both the Win32_UserAccount and Win32_UserProfile.  
      
    .DESCRIPTION
    To Run: Execute this file. (OR)
    To Run: Import-Module .\BT-UserInfo.ps1 -Force
    Note: For Win10 use 'Get-LocalGroupMember -Group Users |Select-Object -Property ObjectClass, Name, PrincipalSource, SID'

    .EXAMPLE
    BT-UserInfo
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
                $UserInfo = New-Object -TypeName PSObject |Select-Object -Property LastUseTime,Type,Caption,Name,FullName,Domain,LocalPath,SID,Description
                # '[System.Management.ManagementDateTimeConverter]::ToDateTime' this converts the 'LastUseTime' into a more human readable format.
                $UserInfo.LastUseTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($Profile.LastUseTime)
                $UserInfo.Type = $Account.AccountType
                $UserInfo.Caption = $Account.Caption
                $UserInfo.Name = $Account.Name
                $UserInfo.FullName = $Account.FullName
                $UserInfo.Domain = $Account.Domain
                $UserInfo.LocalPath = $Profile.localpath
                $UserInfo.SID = $Account.SID
                $UserInfo.Description = $Account.Description
                #Adds each new object into the array.
                $UsersInfo += $UserInfo
            }
        }
    } 
    $UsersInfo
}
#Calling the function below will output the results when run.
BT-UserInfo