function Get-ARP_History {
    <#
    .SYNOPSIS
        
    .DESCRIPTION
    To Run: Import-Module .\Get-ARP_History.psm1 -Force
    Not on WIN7: Get-NetNeighbor -AddressFamily IPv4 |Sort-Object -Unique -Property State -Descending 
    Not on WIN7: Get-NetNeighbor -AddressFamily IPv6 |Sort-Object -Unique -Property State -Descending 
    #>
    [CmdletBinding()]
    param()
    # Raw strings data.
    $Arp_Raw = arp -a
    # This command filters out the headings line (internet address) and removes spaced lines (length -gt 0) because those lines have zero characters on them.
    $Arp_Filtered = $Arp_Raw |Where-Object {$_ -notmatch 'internet address' -and $_.length -gt 0}
    
    # Creates an array outside the loop to input the new objects into later.
    $Arp_Entries = @()

    # Starts a loop that goes through the filtered results one line at a time.
    foreach ($Line in $Arp_Filtered){
        # As each Interface has multiple entries, this 'if' statement selects the first 'interface' line and stores the relivent data in variables until it gets overwritten by the next 'interface' line.
        if ($Line -match 'interface'){
            # This splits by a space, where [1] is the second chunk of data.
            $Interface = $Line.split(' ')[1]
            # This splits by a space, where [-1] is the last chunk of data.
            $Interface_Number = $Line.split(' ')[-1]
         } 
        # When a line doesnt have 'interface' in it, it then goes through the else statement.    
        else{
            # For this line of data a new object is created, which contains new properties 'Internet_Address,Physical_Address,ARP_Type,Interface,Interface_Number'. 
            $Arp_Entry = New-Object -TypeName PSObject |Select-Object -Property Interface,Interface_Number,Internet_Address,Physical_Address,ARP_Type
            # Tells the property 'Internet_Address' within the '$Arp_Entry' object to select the data starting at character '0' for the next '15' characters and trim the rest. (start,keep)
            $Arp_Entry.Internet_Address = $Line.substring(0,15).Trim();
            $Arp_Entry.Physical_Address = $Line.substring(24,17).Trim();
            $Arp_Entry.ARP_Type = $Line.substring(46,7).Trim();
            # Tells the property 'Interface' within the '$Arp_Entry' object to select the data stored within the '$Interface' variable from the 'if' statement.
            $Arp_Entry.Interface = $Interface;
            $Arp_Entry.Interface_Number = $Interface_Number;
            # Adds each new '$Arp_Entry' object into the '$Arp_Entries' array.
            $Arp_Entries += $Arp_Entry
            # Then the loop starts again.
        }
    }
    # Displays the '$Arp_Entry' objects stored in the '$Arp_Entries' array.
    $Arp_Entries
}