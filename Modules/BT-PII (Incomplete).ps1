function BT-InvalidFiles(){
    <#
    .DESCRIPTION
    To Run: Execute this file. (OR)
    To Run: Import-Module .\BT-InvalidFiles.ps1 -Force 
    #>
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'SilentlyContinue' # Disables errors.
    #Raw data from multiple sources.
    $raw = Get-ChildItem -Path 'D:\protected_share' -Recurse
    #$raw4 = (Get-ChildItem -Path 'C:\Users\Windows\AppData\Local\Temp' -Recurse).FullName |ForEach-Object {Get-AuthenticodeSignature -FilePath $_} |Where-Object {$_.Status -ne "Valid"} |Select-Object -Property Status,Path
    #$raw = $raw1 + $raw2 + $raw3 + $raw4
    
    # Creating an array to store filtered information.
    $Filtered = @()
    $raw |ForEach-Object {
        $Return_Data = New-Object -TypeName PSObject |Select-Object -Property Path, CreationTime, LastAccessTime, FileOwner, FileHashSHA1, FileHashSHA256
        $Return_Data.Path = $_.Fullname
        $Return_Data.CreationTime = (Get-ChildItem $Return_Data.Path).CreationTime
        $Return_Data.LastAccessTime = (Get-ChildItem $Return_Data.Path).LastAccessTime
        $Return_Data.FileOwner = ((Get-ItemProperty $Return_Data.Path).GetAccessControl()).Owner
        $Return_Data.FileHashSHA1 = (Get-FileHash -Algorithm SHA1 $Return_Data.Path).Hash
        $return_data.FileHashSHA256 = (Get-FileHash -Algorithm SHA256 $return_data.Path).Hash

        $Filtered += $Return_Data
    }
    $Filtered
}
#Calling the function below will output the results when run.
BT-InvalidFiles