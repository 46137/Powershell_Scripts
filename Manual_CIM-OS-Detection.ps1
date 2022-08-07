#Script Intent: If the device's WinRM is down and RPC port 135 is up, it will leverage that port to run ciminstances.

$comp = '10.10.0.113'
#read-host -assecurestring | convertfrom-securestring | out-file C:\Users\Heady\Desktop\secure.txt <- Run this command once to generate your secure password file. 
$User = "546CMT\Administrator"
$PWord = Get-Content 'C:\Users\Heady\Desktop\secure.txt' | ConvertTo-SecureString
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
$options = New-CimSessionOption -Protocol Dcom #Change between Dcom(135) or Wsman(5985)
$session = New-CimSession -ComputerName $comp -SessionOption $options -Credential $Credential
#Can change classname to query other information.
Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem |Select-Object -Property Caption, Version, CSName, OSArchitecture, WindowsDirectory
Remove-CimSession -CimSession $session