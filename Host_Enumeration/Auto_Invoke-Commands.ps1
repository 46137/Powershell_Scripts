#Script intent: When you want to investigate a potentially compromised endpoints, this can be used to invoke specific commands and save into a local running log.
$DTG = Get-Date -Format "yyMMdd"

#Changing Variables
#read-host -assecurestring | convertfrom-securestring | out-file C:\secure.txt <- Run this command once to generate your secure password file. 
$User = "TL\Heady" #"546CMT\Administrator"
$PWord = Get-Content 'C:\Users\Heady\Desktop\secure.txt' | ConvertTo-SecureString
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord

#Select the hosts text file. E.g. 230220-Hosts-Port-5985
$Endpoints = Get-Content 'C:\Users\Heady\Desktop\230605-Hosts-Port-5985.txt'
foreach ($E in $Endpoints){
    #There are two methods below, invoke a single command or invoke a ps1 script. Comment out the one not needed.
    $Output = Invoke-Command -ComputerName $E -Credential $Credential -ErrorAction SilentlyContinue -ScriptBlock {
    #List below the commands you want to query.      
    gwmi Win32_OperatingSystem |select -ExpandProperty CSName

    }

    #$Output = Invoke-Command -FilePath "C:\Users\Heady\Documents\Powershell_Scripts-1\Host_Enumeration\Modules_Framwork\BT-SysInfo.ps1" -ComputerName $E -Credential $Credential

    #There are two output methods, to a appending text log or json. Comment out the one not needed.
    $Output | Tee-Object -Append C:\Users\heady\Desktop\$DTG-$E-log.txt
    #$Output | ConvertTo-Json | Tee-Object -Append C:\Users\heady\Desktop\$DTG-$E-data.json
}