function BT-SchTsk(){
    <#
    .DESCRIPTION
    To Run: Execute this file. (OR)
    To Run: Import-Module .\BT-SchTsk.ps1 -Force 
    Add: RunKeys
    Add: Get-BitsTransfer
    Add: Services

    #>
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'SilentlyContinue' # Disables errors on permissions when running Get-AuthenticodeSignature.
    #Raw data.
    $schtsk = Get-ScheduledTask
    
    # Creating an array to store filtered scheduled task information from each task.
    $filtered_tasks = @()
    $schtsk |ForEach-Object {
        $return_data = New-Object -TypeName PSObject |Select-Object -Property State,TaskName,LastRunTime,NextRunTime,CreationDate,TaskPath,ExecutablePath,ExecutableAuthCode,FileHashSHA1,FileHashSHA256
        $return_data.State = $_.State
        $return_data.TaskName = $_.TaskName
        $return_data.LastRunTime = ($_ |Get-ScheduledTaskInfo).LastRunTime
        $return_data.NextRunTime = ($_ |Get-ScheduledTaskInfo).NextRunTime
        $return_data.CreationDate = $_.Date
        $return_data.TaskPath = $_.TaskPath
        $return_data.ExecutablePath = ($_.Actions).execute
        $return_data.ExecutableAuthCode = (Get-AuthenticodeSignature -FilePath $return_data.ExecutablePath).Status
        $return_data.FileHashSHA1 = (Get-FileHash -Algorithm SHA1 $return_data.ExecutablePath -ErrorAction SilentlyContinue).Hash
        $return_data.FileHashSHA256 = (Get-FileHash -Algorithm SHA256 $return_data.ExecutablePath -ErrorAction SilentlyContinue).Hash
        $filtered_tasks += $return_data
    }
    $filtered_tasks
}
#Calling the function below will output the results when run. Filters can be added for better human-readability.
BT-SchTsk |Sort-Object -Property CreationDate -Descending

#Detect with SysmonID:19. Shows trigger for execution.
Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Where-Object {$_.Name -ne 'SCM Event Log Filter'}
#Detect with SysmonID:20. Shows actions, e.g. Base64 encoded string, executing files.
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | Where-Object {$_.Name -ne 'SCM Event Log Consumer'}
#Detect with SysmonID:21. Binds Filter and Consumer Classes.
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding  | Where-Object {$_.Consumer -ne 'NTEventLogEventConsumer.Name="SCM Event Log Consumer"'}
