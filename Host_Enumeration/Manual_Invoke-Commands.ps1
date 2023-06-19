#Script intent: When you want to investigate a potentially compromised device, this can be used to invoke specific commands and save into a local running log.

$comp = '172.16.10.101' #'WIN10-TEST'
#read-host -assecurestring | convertfrom-securestring | out-file C:\secure.txt <- Run this command once to generate your secure password file. 
$User = "TL\Heady" #"546CMT\Administrator"
$PWord = Get-Content 'C:\Users\Heady\Desktop\secure.txt' | ConvertTo-SecureString
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
$DTG = Get-Date -Format "yyMMdd"

#There are two methods below, invoke a single command or invoke a ps1 script. Comment out the one not needed.  

$output = Invoke-Command -ComputerName $comp -Credential $Credential -ScriptBlock { 
    #list below the commands you want to query.      
    whoami
}

#$output = Invoke-Command -FilePath C:\Users\Heady\Documents\Powershell_Scripts-1\Modules\BT-SysInfo.ps1 -ComputerName $comp -Credential $Credential

#Displays output to the screen.
$output

#There are two output methods, to a appending text log or json. Comment out the one not needed.
#$output | Out-File -Append C:\Users\heady\Desktop\$DTG-$comp-log.txt
#$output | ConvertTo-Json | Out-File -Append C:\Users\heady\Desktop\$DTG-$comp-data.json