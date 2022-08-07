#Script intent: When you want to investigate a potentially compromised device, this can be used to invoke specific commands and save into a local running log.

$comp = 'WIN10-TEST'
#read-host -assecurestring | convertfrom-securestring | out-file C:\secure.txt <- Run this command once to generate your secure password file. 
$User = "546CMT\Administrator"
$PWord = Get-Content 'C:\Users\Heady\Desktop\secure.txt' | ConvertTo-SecureString
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
$DTG = Get-Date -Format "yyMMdd"

$output = Invoke-Command -ComputerName $comp -Credential $Credential -ScriptBlock { #list below the commands you want to query.
    
whoami
           
}
$output
$output | Out-File -Append C:\Users\heady\Desktop\$DTG-$comp-log.txt