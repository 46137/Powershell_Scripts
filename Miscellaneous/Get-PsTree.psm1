#requires -version 6
using namespace System.Reflection
using namespace System.Runtime.InteropServices

Set-Alias -Name pstree -Value Get-PsTree
function Get-PsTree {
  [CmdletBinding()]
  param()

  begin {
    # CreateToolhelp32Snapshot, Process32First and Process32Next
    ($pinvoke = [PSObject].Assembly.GetType(
      'System.Management.Automation.PlatformInvokes'
    )).GetMethods([BindingFlags]'NonPublic, Static').Where{
      $_.Name -cmatch '\A(CreateT|Process)'
    }.ForEach{ Set-Variable -Name $_.Name -Value $_ }
    # TH32CS_SNAPPROCESS
    $Flags = 2 -as $pinvoke.GetNestedType(
      'SnapshotFlags', [BindingFlags]'NonPublic'
    )
    # helper function for extracting nested processes
    function Get-ChildProcess([PSCustomObject]$Process, [UInt16]$Depth = 1) {
      $pslist.Where{ $_.PPID -eq $Process.PID -and $_.PPID -ne 0 }.ForEach{
        "$("$([Char]32)" * 3 * $Depth)$($_.ImageName) ($($_.PID))"
        Get-ChildProcess $_ (++$Depth)
        $Depth--
      }
    }
  }
  process {}
  end {
    if (( # trying to take processes snapshot
      $snap = $CreateToolhelp32Snapshot.Invoke($null, @($Flags, [UInt32]0))
    ).IsInvalid) {
      Write-Verbose "[-] Could not get processes snapshot."
      return
    }
    # setting PROCESSENTRY32 size
    $PROCESSENTRY32 = [Activator]::CreateInstance(
      $pinvoke.GetNestedType('PROCESSENTRY32', [BindingFlags]'NonPublic')
    )
    $PROCESSENTRY32.dwSize = [Marshal]::SizeOf($PROCESSENTRY32)
    # extracting data fromsnapshot
    if ($Process32First.Invoke($null, (
      $ret = [Object[]]($snap, $PROCESSENTRY32)
    ))) {
      $pslist = do {
        [PSCustomObject]@{
          ImageName = $ret[1].szExeFile
          PID = $ret[1].th32ProcessId
          PPID = $ret[1].th32ParentProcessId
        }
      } while ($Process32Next.Invoke($null, (
        $ret = [Object[]]($snap, $PROCESSENTRY32)
      )))
      # build processes tree
      $pslist.Where{!(
        $p = Get-Process -Id $_.PPID -ErrorAction 0
      ) -or !$p.ProcessName -or $_.PPID -eq 0}.ForEach{
        "$($_.ImageName) ($($_.PID))"
        Get-ChildProcess $_
      }
    }
    else { Write-Verbose "[-] Could not parse snapshot data." }
    # release resources
    $snap.Dispose()
    [GC]::Collect()
  }
}