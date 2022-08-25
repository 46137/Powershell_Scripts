function BT-Process(){
    <#
    .DESCRIPTION
    To Run: Execute this file. (OR)
    To Run: Import-Module .\BT-Process.ps1 -Force 

    #>
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'SilentlyContinue' # Disables errors on permissions when running Get-AuthenticodeSignature.
    #Raw data.
    $proc = Get-WmiObject -Class win32_process
    
    # Creating an array to store filtered information.
    $filtered_proc = @()
    $proc |ForEach-Object {
        $return_data = New-Object -TypeName PSObject |Select-Object -Property CreationDate,PID,PPID,Name,ExecutablePath,ExecutableAuthCode,CommandLine
        $return_data.CreationDate = $_.converttodatetime($_.creationdate)
        $return_data.PID = $_.ProcessID
        $return_data.PPID = $_.ParentProcessID
        $return_data.Name = $_.Name
        $return_data.ExecutablePath = $_.ExecutablePath
        $return_data.ExecutableAuthCode = (Get-AuthenticodeSignature -FilePath $return_data.ExecutablePath).Status #Get-AuthenticodeSignature is slow, disable if needed.
        $return_data.CommandLine = $_.CommandLine
        $filtered_proc += $return_data
    }
    $filtered_proc
}
#Calling the function below will output the results when run.
BT-Process