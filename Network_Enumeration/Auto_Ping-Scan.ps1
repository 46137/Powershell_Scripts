#Script intent: To quicky ping sweep the network.
$DTG = Get-Date -Format "yyMMdd"

#Changing Variables
$Subnets = '172.16.10'#,'172.16.11'
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
            $IP = $_.Address.IPAddressToString
            "$IP - Hosts Up"
        }
    }
}
$Up_Hosts |Out-File -FilePath $FolderPath\$DTG-Hosts-Ping.txt