#Script intent: When you want to investigate a potentially compromised device, this can be used to invoke specific commands and save into a local running log.

#Generic Variables
$DTG = Get-Date -Format "yyMMdd"
#read-host -assecurestring | convertfrom-securestring | out-file C:\Users\Heady\Desktop\secure.txt <- Run this command once to generate your secure password file. 

#Changing Variables
$Subnets = '192.168.0'#,'192.168.65' #Change subnets as required.
$User = "546CMT\Administrator"
$PWord = Get-Content 'C:\Users\Heady\Desktop\secure.txt' | ConvertTo-SecureString
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord

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
    $Address |ForEach-Object {
        #$Output = Invoke-Command -ComputerName $_ -Credential $Credential -FilePath C:\Users\heady\Documents\VSCode-Git\Powershell_Scripts
        $Output = Invoke-Command -ComputerName $_ -Credential $Credential -ScriptBlock { #list below the commands you want to query.
    
        whoami
           
        }
        $Output
        $Output | Out-File -Append C:\Users\heady\Desktop\$DTG-$_-log.txt
    }
}