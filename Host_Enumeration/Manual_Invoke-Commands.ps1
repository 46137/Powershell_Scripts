#Script intent: When you want to investigate a potentially compromised endpoint, this can be used to invoke specific commands and save into a local running log.
$DTG = Get-Date -Format "yyMMdd"

#Changing Variables
$Endpoint = '172.16.10.100' #'WIN10-TEST'
#read-host -assecurestring | convertfrom-securestring | out-file C:\secure.txt <- Run this command once to generate your secure password file. 
$User = "TL\Heady" #"546CMT\Administrator"
$PWord = Get-Content 'C:\Users\Heady\Desktop\secure.txt' | ConvertTo-SecureString
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord

#There are two methods below, invoke a single command or invoke a ps1 script. Comment out the one not needed.  
$Output = Invoke-Command -ComputerName $Endpoint -Credential $Credential -ErrorAction SilentlyContinue -ScriptBlock { 
    #list below the commands you want to query.      
    gwmi Win32_OperatingSystem |select -ExpandProperty CSName
}

#$Output = Invoke-Command -FilePath C:\Users\Heady\Documents\Powershell_Scripts-1\Modules\BT-SysInfo.ps1 -ComputerName $Endpoint -Credential $Credential

#There are two output methods, to a appending text log or json. Comment out the one not needed.
$Output | Tee-Object -Append C:\Users\heady\Desktop\$DTG-$Endpoint-log.txt
#$Output | ConvertTo-Json | Tee-Object -Append C:\Users\heady\Desktop\$DTG-$Endpoint-data.json