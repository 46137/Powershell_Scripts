#Script intent: To quicky port scan the network to determine remoting access.
$DTG = Get-Date -Format "yyMMdd"

#Changing Variables
$Subnets = "172.16.10."#,"172.16.11."
$IPs = 1..255
$Port = 5985 #Common ports: 135(Domain),5985/6(WinRM),22(SSH),3389(RDP)
$TimeoutMilliseconds = 50
$FolderPath = "C:\Users\heady\Desktop"

$Open_Port = @()
foreach ($Subnet in $Subnets){
    $IPs | ForEach-Object{
        $IP = $Subnet + $_
        $Socket = [System.Net.Sockets.TcpClient]::new()
        $Result = $Socket.BeginConnect($IP, $Port, $null, $null) # Null 1 is optional callback methods, null 2 is operation state for callback method.
        $Success = $Result.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)
            if ($Success -and $Socket.Connected){
                $Open_Port += $IP
                "$IP - Open Port: $Port"
                $Socket.Close()
            }
        Write-Progress -Activity "Scanning Network" -Status "$Subnet$_" -PercentComplete (($_/($IPs.Count))*100) # Progress bar.
    }
    $Open_Port |Out-File -FilePath $FolderPath\$DTG-Hosts-"Port-$Port".txt
}
    