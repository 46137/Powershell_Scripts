<#
Script intent: To call on the pre-made modules, modules will differ depending on the endpoint.

Tasks:
- 

#>

#Changing Variables
$FolderPath = "C:\Users\Heady\Documents\VSCode-Git\Powershell_Scripts\Modules"

Invoke-Expression -Command $FolderPath\BT-SysInfo.ps1
Invoke-Expression -Command $FolderPath\BT-SchTsk.ps1
Invoke-Expression -Command $FolderPath\BT-SchTskOld.ps1