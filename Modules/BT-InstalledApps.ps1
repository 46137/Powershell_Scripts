function BT-Template(){
    <#
    .DESCRIPTION
    To Run: Execute this file. (OR)
    To Run: Import-Module .\BT-Template.ps1 -Force 

    #>
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'SilentlyContinue' # Disables errors.
    #Raw data.
    $raw = Get-RawData
Get-WmiObject -Class Win32_Product
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object InstallDate, DisplayIcon, DisplayName, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending |Format-Table -AutoSize #lists 32bit programs
Get-ItemProperty HKLM:\software\microsoft\windows\currentversion\Uninstall\* |Select-Object InstallDate, DisplayName, DisplayIcon, DisplayVersion, Publisher, InstallSource |Sort-Object InstallDate -Descending |Format-Table -Wrap #lists 64bit programs

Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | ForEach-Object {Get-ItemProperty $_.psPath} | FL InstallLocation

Get-Item 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{7118A6E9-9641-4025-A3F1-F6650A3B7FB0}' |Select-Object -Property *
Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{7118A6E9-9641-4025-A3F1-F6650A3B7FB0}
Get-ItemProperty 'HKLM:\software\microsoft\windows\currentversion\Uninstall\{7118A6E9-9641-4025-A3F1-F6650A3B7FB0}' |Select-Object -Property * # InstallDate, DisplayIcon

    # Creating an array to store filtered information.
    $Filtered = @()
    $raw |ForEach-Object {
        $Return_Data = New-Object -TypeName PSObject |Select-Object -Property Name
        $Return_Data.Name = $_.Name

        $Filtered += $Return_Data
    }
    $Filtered
}
#Calling the function below will output the results when run.
BT-Template