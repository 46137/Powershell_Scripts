#Script intent: When you want to investigate a potentially compromised device, this can be used to invoke specific commands and save into a local running log.

#read-host -assecurestring | convertfrom-securestring | out-file C:\secure.txt <- Run this command once to generate your secure password file. 
$User = "TL\Heady" #"546CMT\Administrator"
$PWord = Get-Content 'C:\Users\Heady\Desktop\secure.txt' | ConvertTo-SecureString
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
$DTG = Get-Date -Format "yyMMdd"

#Select the hosts text file. E.g. 230220-Hosts-Port-5985
$Hosts = Get-Content 'C:\Users\Heady\Desktop\230605-Hosts-Port-5985.txt'
foreach ($H in $Hosts){

    #There are two methods below, invoke a single command or invoke a ps1 script. Comment out the one not needed.
    $output = Invoke-Command -ComputerName $H -Credential $Credential -ScriptBlock {
    #list below the commands you want to query.      
    whoami

    }

    #$output = Invoke-Command -FilePath "C:\Users\Heady\Documents\Powershell_Scripts-1\Host_Enumeration\Modules_Framwork\BT-SysInfo.ps1" -ComputerName $H -Credential $Credential

    #Displays output to the screen.
    $output

    #There are two output methods, to a appending text log or json. Comment out the one not needed.
    $output | Out-File -Append C:\Users\heady\Desktop\$DTG-$H-log.txt
    #$output | ConvertTo-Json | Out-File -Append C:\Users\heady\Desktop\$DTG-$H-data.json
}