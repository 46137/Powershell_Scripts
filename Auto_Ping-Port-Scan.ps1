#Script intent: To quicky ping sweep the network and determine if remoting ports are up.

$ErrorActionPreference = 'SilentlyContinue' # Disables errors. Errors will occur on failed ports.
$Subnets = '192.168.65','192.168.0' #Change subnets as required.
foreach ($Subnet in $Subnets){
    $IPs = 1..254 | ForEach-Object {"$($Subnet).$_"}
    $Ping = $IPs|ForEach-Object {
        #(New-Object Net.NetworkInformation.Ping).SendPingAsync($_,250) 
        [Net.NetworkInformation.Ping]::New().SendPingAsync($_, 250) #PowerShell v5
    }
    [Threading.Tasks.Task]::WaitAll($Ping)
    $UPHosts = $Ping.Result | ForEach-Object {if($_.Status -eq 'Success'){$_}} #Selects only the up hosts.
    [System.DateTime]::now | Out-File -Append C:\Users\heady\Desktop\$Subnet-PingSweep.txt #Save current time to associate with the output.
    $UPHosts |Select-Object -Property Address,Status,RoundtripTime | Out-File -Append C:\Users\heady\Desktop\$Subnet-PingSweep.txt #Saves the ping output.
    $UPHosts |Select-Object -Property Address,Status,RoundtripTime #Lists the ping output to the screen.
    $Address = $UPHosts |ForEach-Object {$_.Address.IPAddressToString}
#Everything above will get a string of the up hosts.
    $Ports = '5985'#,'135','22','3389' #Change ports as required.
    $Address |ForEach-Object {
        foreach ($Port in $Ports){
            $Socket = New-Object System.Net.Sockets.TcpClient($_, $Port)
            If($Socket.Connected){
                "$_ - Open Port: $Port" 
                [System.DateTime]::now | Out-File -Append C:\Users\heady\Desktop\$_-PortScan.txt
                "$_ - Open Port: $Port" | Out-File -Append C:\Users\heady\Desktop\$_-PortScan.txt
                $Socket.Close()
            }
        }
    }
}