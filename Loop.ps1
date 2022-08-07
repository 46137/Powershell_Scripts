
$Subnet = '192.168.0' #Change subnet
$DTG = Get-Date -Format "yyMMddHHmm"
$IPs = 1..254 | ForEach-Object {"$($Subnet).$_"}
$Ping = $IPs|ForEach-Object {
    #(New-Object Net.NetworkInformation.Ping).SendPingAsync($_,250) 
    [Net.NetworkInformation.Ping]::New().SendPingAsync($_, 250) #PowerShell v5
    }
[Threading.Tasks.Task]::WaitAll($Ping)
$UPHosts = $Ping.Result | ForEach-Object {if($_.Status -eq 'Success'){$_}}
[System.DateTime]::now | Out-File -Append C:\Users\heady\Desktop\$Subnet-PingSweep.txt
$UPHosts |Select-Object -Property Address,Status,RoundtripTime | Out-File -Append C:\Users\heady\Desktop\$Subnet-PingSweep.txt
$Address = $UPHosts |ForEach-Object {$_.Address.IPAddressToString}
$Address |ForEach-Object {
    $out = Test-NetConnection -Port 5985 -ComputerName $_ |Select-Object -Property ComputerName,RemotePort,TcpTestSucceeded
    if (($out).TcpTestSucceeded -eq 'True'){
        $out
    }
}

#TcpTestSucceeded : True

