function BT-Netstat(){
    <#
    .DESCRIPTION
    To Run: Execute this file. (OR)
    To Run: Import-Module .\BT-Netstat.ps1 -Force 

    Ingergrate Get-NetUDPEndpoint

    #>
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'SilentlyContinue' # Disables errors.
    #Raw data.
    $raw1 = Get-NetTCPConnection
    $raw2 = Get-NetUDPEndpoint
    $raw = $raw1 + $raw2

    # Creating an array to store filtered information.
    $Filtered = @()
    $raw |ForEach-Object {
        $Return_Data = New-Object -TypeName PSObject |Select-Object -Property CreationTime, PID, ProcessName, State, SrcAddress, SrcPort, DstAddress, DstPort, NetworkProfile, Protocol, ExecutablePath 
        $Return_Data.CreationTime = $_.CreationTime
        $Return_Data.PID = $_.OwningProcess
        $Return_Data.ProcessName = (Get-Process -Id $_.OwningProcess).ProcessName
        $Return_Data.State = $_.State
        $Return_Data.SrcAddress = $_.LocalAddress
        $Return_Data.SrcPort = $_.LocalPort
        $Return_Data.DstAddress = $_.RemoteAddress
        $Return_Data.DstPort = $_.RemotePort
        $Return_Data.NetworkProfile = $_.AppliedSetting
        $Return_Data.Protocol = if ($_.CimClass -like '*NetUDPEndpoint*') { 'UDP' } else { 'TCP' } 
        $Return_Data.ExecutablePath = (Get-Process -Id $_.OwningProcess).Path

        $Filtered += $Return_Data
    }
    $Filtered
}
#Calling the function below will output the results when run.
BT-Netstat |Sort-Object -Property CreationTime |Format-Table -Wrap