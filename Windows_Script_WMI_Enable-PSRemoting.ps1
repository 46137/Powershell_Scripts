#Script Intent: If the device's WinRM is down and RPC port 135 is up, it will leverage that port to enable-psremoting.

#read-host -assecurestring | convertfrom-securestring | out-file C:\Users\Heady\Desktop\secure.txt <- Run this command once to generate your secure password file. 
$User = "546CMT\Administrator"
$PWord = Get-Content 'C:\Users\Heady\Desktop\secure.txt' | ConvertTo-SecureString
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord

$SessionArgs = @{
    ComputerName  = '10.10.0.117'
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
