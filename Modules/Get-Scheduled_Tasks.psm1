function Get-Scheduled_Tasks {
    <#
    .SYNOPSIS
        
    .DESCRIPTION
    Note: Get-ScheduledTask not on WIN7
    To Run: Import-Module .\Get-Scheduled_Tasks.psm1 -Force
    #>
    [CmdletBinding()]
    param()
    # Raw strings data.
    $Tasks_Raw = schtasks /query
    # This command filters out the headings line (TaskName), the equals lines (======) and removes spaced lines (length -gt 0) because those lines have zero characters on them.
    $Tasks_Filtered = $Tasks_Raw |Where-Object {$_ -notmatch 'TaskName' -and $_ -notmatch '========' -and $_.length -gt 0}
    
    # Creates an array outside the loop to input the new objects into later.
    $Tasks_Entries = @()

    # Starts a loop that goes through the filtered results one line at a time.
    foreach ($Line in $Tasks_Filtered){
        # As each 'Folder:' has multiple entries, this 'if' statement selects the first 'Folder:' line and stores the relivent data in variables until it gets overwritten by the next 'Folder:' line.
        if ($Line -match 'Folder:'){
            # This splits by a colon, where [1] is the second chunk of data.
            $Folder = $Line.split(':')[1]
        } 
        # When a line doesnt have 'Folder:' in it, it then goes through the else statement.    
        else{
            # Some task paths that do not currently have any tasks will display an info line. To remove it, it is sent to a '$bin' variable in the following 'if' statement.
            if ($Line -match 'INFO:'){
                $bin
            }
            else{
                # For this line of data a new object is created, which contains new properties 'Task_Path,Task_Name,Next_Run_Time,Status'. 
                $Tasks_Entry = New-Object -TypeName PSObject |Select-Object -Property Task_Path,Task_Name,Next_Run_Time,Status
                # Tells the property 'Task_Name' within the '$Tasks_Entry' object to select the data starting at character '0' for the next '41' characters and trim the rest. (start,keep)
                $Tasks_Entry.Task_Name = $Line.substring(0,41).Trim();
                $Tasks_Entry.Next_Run_Time = $Line.substring(41,20).Trim();
                $Tasks_Entry.Status = $Line.substring(64,8).Trim();
                # Tells the property 'Task_Path' within the '$Tasks_Entry' object to select the data stored within the '$Folder' variable from the 'if' statement.
                $Tasks_Entry.Task_Path = $Folder;
                # Adds each new '$Tasks_Entry' object into the '$Tasks_Entries' array.
                $Tasks_Entries += $Tasks_Entry
                # Then the loop starts again.
            }
        }    
    }
    # Displays the '$Tasks_Entry' objects stored in the '$Tasks_Entries' array.
    $Tasks_Entries
}