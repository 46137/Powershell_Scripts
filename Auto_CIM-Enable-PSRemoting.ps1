#Script intent: To Enable-PSRemoting on Windows hosts that have port 135 open.
$ErrorActionPreference = 'SilentlyContinue' # Disables errors. Errors will occur on failed ports.

#Changing Variables
$Subnets = '192.168.0'#,'192.168.65','172.16.10','172.16.11'
$Credential = Get-Credential -Credential TL\Heady
$Output = 'C:\Users\heady\Desktop\Enable-PSRemoting-Results.txt'

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
[System.DateTime]::now |Tee-Object -Append $Output
$Up_Hosts |Tee-Object -Append $Output

#Using active hosts, checks if port 135 is open.
$135_Open = @()
$Up_Hosts |ForEach-Object {
    $Socket = New-Object System.Net.Sockets.TcpClient($_, 135)
    If($Socket.Connected){
        $135_Open += $_
        "$_ - Open Port: 135" |Tee-Object -Append $Output
        $Socket.Close()
    }    
}

#Will try to enable-psremoting on hosts that have port 135 open.
foreach ($o in $135_Open){
    $SessionArgs = @{
        ComputerName  = $o
        Credential    = Get-Credential $Credential
        SessionOption = New-CimSessionOption -Protocol Dcom
    }
    $MethodArgs = @{
        ClassName     = 'Win32_Process'
        MethodName    = 'Create'
        CimSession    = New-CimSession @SessionArgs
        Arguments     = @{
            CommandLine = "powershell Start-Process powershell -ArgumentList 'Enable-PSRemoting -Force'"
        }
    }
    Invoke-CimMethod @MethodArgs #invokes a method of a CIM class or CIM instance using the name-value pairs specified by the Arguments parameter.
}