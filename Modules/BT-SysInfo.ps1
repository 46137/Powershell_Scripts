function BT-SysInfo(){
    <#
    .DESCRIPTION
    To Run: Execute this file. (OR)
    To Run: Import-Module .\BT-SysInfo.ps1 -Force 

    #>
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'SilentlyContinue' # Disables errors.
    #Raw data.
    $datetime = [System.DateTime]::now
    $timezone = [System.TimeZoneInfo]::Local
    $osinfo = Get-WmiObject -Class Win32_OperatingSystem
    
    # Creating an array to store filtered information.
    $Filtered = New-Object -TypeName PSObject |Select-Object -Property DateTime, HostName, TimeZoneName, TimeZone, OSName, OSVersion, OSArchitecture, WindowsDirectory
    $Filtered.DateTime = $datetime
    $Filtered.HostName = ($osinfo).CSName
    $Filtered.TimeZoneName = ($timezone).Id
    $Filtered.TimeZone = ($timezone).DisplayName
    $Filtered.OSName = ($osinfo).Caption
    $Filtered.OSVersion = ($osinfo).Version
    $Filtered.OSArchitecture = ($osinfo).OSArchitecture
    $Filtered.WindowsDirectory = ($osinfo).WindowsDirectory

    $Filtered

}
#Calling the function below will output the results when run. Filters can be added for better human-readability.
BT-SysInfo

#Adding in active interfaces.
Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"} |Select-Object -Property InterfaceAlias,NetProfile.Name,IPv4Address,IPv4DefaultGateway,DNSServer,InterfaceDescription