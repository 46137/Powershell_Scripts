$ErrorActionPreference = 'SilentlyContinue' # Disables errors. Errors will occur on failed ports.
$Subnets = '172.16.10','172.16.11' #Change subnets as required.
#$Credential = Get-Credential -Credential TL\Heady
$Output = 'C:\Users\heady\Desktop\Enable-PSRemoting-Results.txt'

#Creates an array of active hosts.
$Up_Hosts = @()
foreach ($Subnet in $Subnets){
    $IPs = 1..254 | ForEach-Object {"$($Subnet).$_"}
    $Ping = $IPs|ForEach-Object {
        #(New-Object Net.NetworkInformation.Ping).SendPingAsync($_,250) 
        [Net.NetworkInformation.Ping]::New().SendPingAsync($_, 250) #PowerShell v5
    }
    [Threading.Tasks.Task]::WaitAll($Ping)
    $Ping.Result | ForEach-Object {
        if($_.Status -eq 'Success'){
            $Up_Hosts += $_.Address.IPAddressToString
            }
        }
    }
[System.DateTime]::now |Tee-Object -Append $Output
Write-Host '-= ACTIVE HOSTS =-'
'-= ACTIVE HOSTS =-' |Out-File -Append $Output
$Up_Hosts |Tee-Object -Append $Output

#Using active hosts, checks if port 135 is open.
$135_Open = @()
$Up_Hosts |ForEach-Object {
    $Socket = New-Object System.Net.Sockets.TcpClient($_, 135)
    If($Socket.Connected){
        $135_Open += $_
        $Socket.Close()
    }    
}
Write-Host '-= PORT 135 OPEN =-'
'-= PORT 135 OPEN =-' |Out-File -Append $Output
$135_Open |Tee-Object -Append $Output

