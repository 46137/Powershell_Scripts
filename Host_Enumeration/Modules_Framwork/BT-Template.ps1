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