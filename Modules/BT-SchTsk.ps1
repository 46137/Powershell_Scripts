function BT-SchTsk(){
    <#
    .DESCRIPTION
    To Run: Execute this file. (OR)
    To Run: Import-Module .\BT-SchTsk.ps1 -Force 

    #>
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'SilentlyContinue' # Disables errors on permissions when running Get-AuthenticodeSignature.
    #Raw data.
    $schtsk = Get-ScheduledTask
    
    # Creating an array to store filtered scheduled task information from each task.
    $filtered_tasks = @()
    $schtsk |ForEach-Object {
        $return_data = New-Object -TypeName PSObject |Select-Object -Property State,TaskName,LastRunTime,CreationDate,TaskPath,ExecutablePath,ExecutableAuthCode
        $return_data.State = $_.State
        $return_data.TaskName = $_.TaskName
        $return_data.LastRunTime = ($_ |Get-ScheduledTaskInfo).LastRunTime
        $return_data.CreationDate = $_.Date
        $return_data.TaskPath = $_.TaskPath
        $return_data.ExecutablePath = ($_.Actions).execute
        $return_data.ExecutableAuthCode = (Get-AuthenticodeSignature -FilePath $return_data.ExecutablePath).Status
        $filtered_tasks += $return_data
    }
    $filtered_tasks
}
#Calling the function below will output the results when run.
BT-SchTsk