$Input_File = Get-Content -Path C:\Users\Work\Desktop\220704-WIN10-TEST-KeyTerrain.txt
$DTG = Get-Date -Format "yyMMdd"

$IOC_List = Get-Content -path C:\Users\Work\Desktop\IOCs.txt
foreach ($I in $IOC_List){

    $Comparison = $Input_File | Select-String -Pattern $I
    if ($Comparison -ne $null){
    
        [System.DateTime]::now | Out-File -Append C:\Users\work\Desktop\$DTG-Discovered_IOCs.txt
        "=== IOC $I FOUND ===" | Out-File -Append C:\Users\work\Desktop\$DTG-Discovered_IOCs.txt
        $Comparison | Out-File -Append C:\Users\work\Desktop\$DTG-Discovered_IOCs.txt

    }
}