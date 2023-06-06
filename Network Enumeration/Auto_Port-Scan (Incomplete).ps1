# TCP Port Scan network to determine any machines active on the network - Windows/Domain Active Machine focused.


$Network = "172.16.10."
$Fourth_octet = 1..255
$port = 5985
$timeoutMilliseconds = 50  # milliseconds
    
$tcpResults = $Fourth_octet | ForEach-Object {
    
    $ip = $Network + $_ # construction of network address
    $tcpClient = [System.Net.Sockets.TcpClient]::new()
    $result = $tcpClient.BeginConnect($ip, $port, $null, $null) # Null 1 is optional callback methods, null 2 is operation state for callback method
    $success = $result.AsyncWaitHandle.WaitOne($timeoutMilliseconds)
    
    if ($success -and $tcpClient.Connected) {
        "$ip - Open Port: $port"
        $tcpClient.Close()
    }
     Write-Progress -Activity "Scanning Network" -Status "$Network$_" -PercentComplete (($_/($Fourth_octet.Count))*100) # Progress bar
}  
$tcpResults
    