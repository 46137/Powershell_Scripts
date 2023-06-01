function BT-InstalledApps(){
    <#
    .DESCRIPTION
    To Run: Execute this file. (OR)
    To Run: Import-Module .\BT-InstalledApps.ps1 -Force 
    #>
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'SilentlyContinue' # Disables errors.
    #Raw data.
    $raw1 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
    $raw2 = Get-ItemProperty HKLM:\software\microsoft\windows\currentversion\Uninstall\*
    $raw = $raw1 + $raw2

    # Creating an array to store filtered information.
    $Filtered = @()
    $raw |ForEach-Object {
        $Return_Data = New-Object -TypeName PSObject |Select-Object -Property InstallDate, Name, Version, Publisher, DisplayIcon, InstallSource
        $Return_Data.InstallDate = $_.InstallDate
        $Return_Data.Name = $_.DisplayName
        $Return_Data.Version = $_.DisplayVersion
        $Return_Data.Publisher = $_.Publisher
        $Return_Data.DisplayIcon = $_.DisplayIcon
        $Return_Data.InstallSource = $_.InstallSource
        
        $Filtered += $Return_Data
    }
    $Filtered
}
#Calling the function below will output the results when run. Filters can be added for better human-readability.
BT-InstalledApps |Sort-Object -Property InstallDate -Descending 