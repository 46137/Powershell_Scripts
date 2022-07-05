function Get-Login_History {
    <#
    .SYNOPSIS
        
    .DESCRIPTION
    # Admin privileges requried for Get-Eventlog commandlet.    
    # This is incomplete. Couldn't figure out how to pull individual line information. 
    #>
    [CmdletBinding()]
    param(
        [INT] $Entries = 2
    )
    #EventID 4624 = Successful Login.
    $Logs_Raw = Get-EventLog -LogName Security -InstanceId 4624 -Newest $Entries |Select-Object -Property Index, EntryType, TimeGenerated, Message |Format-Table -Wrap
    #EventID 4625 = Failed Login.
    #Get-EventLog -LogName Security -InstanceId 4625 -Newest $Entries |Select-Object -Property Index, EntryType, TimeGenerated, Message
    #EventID 4672 = Login with Admin.
    #Get-EventLog -LogName Security -InstanceId 4672 -Newest $Entries |Select-Object -Property Index, EntryType, TimeGenerated, Message
    #$Logs_Raw
    foreach ($line in $Logs_Raw) {
        if ($line -match 'SuccessAudit') {
            echo $line
        }
        else {
            $null
        }
    }
}




#Index,EntryType,TimeGenerated, Message