#Script intent: To quicky ping sweep the network and determine if remoting ports are up.
#Note: If ping is disabled it won't port scan.
$ErrorActionPreference = 'SilentlyContinue' # Disables errors. Errors will occur on failed ports.
$DTG = Get-Date -Format "yyMMdd"

#Changing Variables
$Subnets = '172.16.10'#,'172.16.11'
$Ports = '5985','135'#,'22','3389'
$FolderPath = "C:\Users\heady\Desktop"

#Creates an array of active hosts via ICMP.
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
$Up_Hosts |Tee-Object -FilePath $FolderPath\$DTG-Hosts-Ping.txt

#Using active hosts, checks if ports are open.
$Ports |ForEach-Object {
$Open_Port = @()    
    foreach ($H in $Up_Hosts){
        $Socket = New-Object System.Net.Sockets.TcpClient($H, $_)
        If($Socket.Connected){
            $Open_Port += $H
            "$H - Open Port: $_"
            $Socket.Close()
        }
    }
    #Added 'if' statement so it doesn't create empty files.
    if ($Open_Port -ne $null) {
        $Open_Port |Out-File -FilePath $FolderPath\$DTG-Hosts-"Port-$_".txt
    }
}