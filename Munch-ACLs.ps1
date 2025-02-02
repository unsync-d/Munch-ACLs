function Munch-ACLs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$Users,  # List of users to check privileges for

        [Parameter(Mandatory = $false)]
        [string[]]$Groups, # List of groups to check privileges for

        [Parameter(Mandatory = $false)]
        [string]$Domain,  # Specify a domain to act on (optional)

        [Parameter(Mandatory = $false)]
        [string[]]$Privs,  # Custom list of privileges to check (optional)

        [Parameter(Mandatory = $false)]
        [switch]$IN,  # Check privileges that everyone has over the subjects

        [Parameter(Mandatory = $false)]
        [switch]$OUT,  # Check privileges that subjects have over others

        [Parameter(Mandatory = $false)]
        [int]$Jitter = 0,  # Jitter in milliseconds (default 0, no delay)

        [Parameter(Mandatory = $false)]
        [int]$BatchSize = 10  # Number of objects to process per batch
    )


    function Invoke-Jitter {
        if ($Jitter -gt 0) {
            $delay = Get-Random -Minimum 1 -Maximum $Jitter
            Write-Verbose "Introducing jitter delay: $delay ms"
            Start-Sleep -Milliseconds $delay
        }
    }

    function Get-Subjects {
        param (
            [string[]]$Users,
            [string[]]$Groups,
            [string]$Domain,
            [switch]$IncludeWellKnown
        )
        $subjects = @()

        # Add well-known groups if in OUT mode
        if ($IncludeWellKnown) {
            $subjects += [PSCustomObject]@{Name = "Authenticated Users"; DN = $null; SID = "S-1-5-11"; Type = "Security Principal"}
            $subjects += [PSCustomObject]@{Name = "Everyone"; DN = $null; SID = "S-1-1-0"; Type = "Security Principal"}
        }

        # Add users
        if ($Users) {
            foreach ($user in $Users) {
                try {
                    $userObj = Get-ADUser -Identity $user -ErrorAction Stop -Server $Domain
                    $subjects += [PSCustomObject]@{
                        Name = $userObj.Name
                        DN   = $userObj.DistinguishedName
                        SID  = $userObj.SID
                        Type = "User"
                    }
                } catch {
                    Write-Warning "Failed to process user $($user): $($_.Exception.Message)"
                }
            }
        }

        # Add groups
        if ($Groups) {
            foreach ($group in $Groups) {
                try {
                    $groupObj = Get-ADGroup -Identity $group -ErrorAction Stop -Server $Domain
                    $subjects += [PSCustomObject]@{
                        Name = $groupObj.Name
                        DN   = $groupObj.DistinguishedName
                        SID  = $groupObj.SID
                        Type = "Group"
                    }
                } catch {
                    Write-Warning "Failed to process group $($group): $($_.Exception.Message)"
                }
            }
        }

        return $subjects
    }

    function Get-ACLsForObject {
        param (
            [object]$Object,
            [string[]]$TargetPermissions,
            [string[]]$OUPermissions,
            [string]$Domain,
            [string]$ChildDomain,
            [string]$PSDrive,
            [object[]]$Subjects,
            [object[]]$ExtendedChecks
        )
        $results = @()
        $matchxs = @()
        if ($null -ne $ExtendedChecks) {$results += $ExtendedChecks}

        foreach ($subject in $Subjects) {
            Invoke-Jitter

            if ($null -eq $Object) {
                try {
                    $regACLs = (Get-ACL "$($psdrive):$($Subject.DN)").Access
                    $regACLs = $regACLs | Where-Object {
                        (($_.ActiveDirectoryRights -split ',\s*') | Where-Object { $TargetPermissions -contains $_ }) -gt 0
                    }
                    $matchxs += $regACLs
                } catch {
                    throw "Failed to retrieve ACLs for $($Subject.DistinguishedName): $_"                   
                }
            } elseif ($Object?.ObjectClass -eq "organizationalUnit") {
                $ouACLs = $regACLs | Where-Object {
                    (($_.ActiveDirectoryRights -split ',\s*') | Where-Object { $OUPermissions -contains $_ }) -gt 0
                }
                $matchxs += $ouACLs
            } else {
                try {
                    $acls = (Get-ACL "$($PSDrive):$($Object.DistinguishedName)").Access
                    $regACLs = $acls | Where-Object { $_.IdentityReference -eq "$ChildDomain\$($subject.Name)" }    
                    $regACLs = $regACLs | Where-Object {
                        (($_.ActiveDirectoryRights -split ',\s*') | Where-Object { $TargetPermissions -contains $_ }) -gt 0
                    }
 
                    $repACLs = $regACLs | ? {$_.AccessControlTpye -eq "Allow" -and $_.ObjectAceType -match "replication-get"}
                    
                    $matchxs += $regACLs 
                    $matchxs += $msMcsAdmPwdMatches
                    $matchxs += $msMcsAdmPwdWriteMatches 
                    $matchxs += $repACLs
                } catch {
                    throw "Failed to retrieve ACLs for $($Object.DistinguishedName): $_"                   
                }
            }

            if ($null -ne $matchxs) {
                $results += $matchxs | ForEach-Object {
                    [PSCustomObject]@{
                        SubjectName        = if ($Object) {$subject.Name} else {$_.IdentityReference.toString()}
                        SubjectType        = if ($Object) {$subject.Type} else { "N/A" }
                        ObjectName         = if ($Object) {$Object.Name} else {$subject.Name}
                        ObjectDistinguishedName = if ($Object) {$Object.DistinguishedName} else {$Subject.DN}
                        Rights             = $_.ActiveDirectoryRights
                        ObjectType         = if ($Object -and $Object.objectClass) {$Object.objectclass -join "->"} 
                                                        elseif ($subject -and $subject.Type) { $subject.Type } 
                                                                else { "N/A" }
                    }
                }
            }
        }
        return $results
    }

    function Invoke-SumResults {
        param (
            [object[]]$Results
        )


        #$Results | ForEach-Object { Write-Host ($_ | Out-String) }

        $SummarizableGroups = @(
            @("GenericRead", "GenericWrite", "GenericAll"),
            @("WriteDacl", "WriteOwner", "GenericAll")
        )

        $summarizedResults = @()
        foreach ($Group in $SummarizableGroups) {
            $MatchingPermissions = $Results | Where-Object {
                (($_.ActiveDirectoryRights -split ',\s*') | Where-Object { $Group -contains $_ }) -gt 1
            }

            # If permissions match a summarizable group, summarize to the highest level
            if ($MatchingPermissions.Count -gt 0) {
                $HighestPermission = $Group | Where-Object {
                    $MatchingPermissions.Rights -contains $_
                } | Sort-Object { [Array]::IndexOf($Group, $_) } | Select-Object -Last 1

                # Add the summarized permission
                $summarizedResults += $Results | Where-Object {
                    $_.Rights -eq $HighestPermission
                }

                # Remove already summarized permissions from the remaining matches
                $Results = $Results | Where-Object {
                    (($_.ActiveDirectoryRights -split ',\s*') | Where-Object { $Group -contains $_ }) -lt 1
                }

            }
        }

        # Add any remaining non-summarizable permissions
        $summarizedResults += $Results       
        return $summarizedResults
    }

    function Show-Results {
        param ($Results)
        #Write-Host $Results
        # Split into high-risk and normal results
        $highRisk = $Results | Where-Object {
            $_.Rights -match "GenericAll|WriteDacl|WriteOwner|AllExtendedRights"
        }

        $other =  $Results | Where-Object {
            (($_.ActiveDirectoryRights -split ',\s*') | Where-Object { @("GenericAll", "WriteDacl", "WriteOwner", "AllExtendedRights") -notcontains $_ }) 
        }

        if ($highRisk) {
            Write-Host "`n=== HIGH RISK PERMISSIONS ===" -ForegroundColor Red
            $highRisk | ForEach-Object {
                Write-Host ("[{0}] {1} -> [{2}] {3} : {4}" -f 
                    $_.SubjectType,
                    $_.SubjectName.PadRight(5),
                    $($_.ObjectType -split "->" | Select-Object -Last 1),
                    $_.ObjectName.PadRight(5),
                    $_.Rights) -ForegroundColor Red
            }
        }

        if ($other) {
            Write-Host "`n=== OTHER PERMISSIONS ===" -ForegroundColor Cyan
            $other | ForEach-Object {
                Write-Host ("[{0}] {1} -> [{2}] {3} : {4}" -f 
                    $_.SubjectType,
                    $_.SubjectName.PadRight(5),
                    $($_.ObjectType -split "->" | Select-Object -Last 1),
                    $_.ObjectName.PadRight(5),
                    $_.Rights) -ForegroundColor White
            }
        }

        # Summary table
        Write-Host "`n=== SUMMARY TABLE ===" -ForegroundColor Green
        $Results | Sort-Object SubjectName | Format-Table -AutoSize -Wrap @{
            Label = "Subject"
            Expression = { $_.SubjectName }
        },@{
            Label = "SubjectType"
            Expression = { $_.SubjectType }
        }, @{
            Label = "Target"
            Expression = { $_.ObjectName }
        }, @{
            Label = "TargetType"
            Expression = { $_.ObjectType  }
        }, @{
            Label = "Permission"
            Expression = { 
                if ($_.Rights -match "GenericAll|WriteDacl") { 
                    "$($_.Rights) !!" 
                } else { 
                    $_.Rights 
                }
            }
        }
    }

    function Resolve-GUID {
        param ($ObjectGUID)
        try {
            Invoke-Jitter
            $resolvedObject = Get-ADObject -Filter { ObjectGUID -eq $ObjectGUID } -Properties Name -Server $Domain
            return $resolvedObject.Name
        } catch {
            Write-Warning "Failed to resolve GUID $($ObjectGUID): $($_.Exception.Message)"
            return $ObjectGUID
        }
    }

    # Validate parameters
    if ($IN -and $OUT) {
        throw "Only one of -IN or -OUT can be specified."
    }

    # Define default permissions
    $defaultPermissions = @(
        "FullControl", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
        "WriteProperty", "CreateChild", "AllExtendedRights", "ForceChangePassword"
    )

    # Define high-risk permissions to look for
    $OUPermissions = @(
        "GenericAll",      # Full control over an object
        "WriteDacl",       # Modify DACL (permissions)
        "WriteOwner",      # Modify the owner of an object
        "AllExtendedRights", # Extended rights (can include admin privileges)
        "ForceChangePassword" # Ability to change passwords
    )

    # Validate user-provided privileges
    if ($Privs) {
        $invalidPrivs = $Privs | Where-Object { $_ -notin $defaultPermissions }
        if ($invalidPrivs) {
            throw "Invalid privileges detected: $($invalidPrivs -join ', '). Valid privileges are: $($defaultPermissions -join ', ')"
        }
        $targetPermissions = $Privs
    } else {
        $targetPermissions = $defaultPermissions
    }

    # Set domain and distinguished name
    $currentDomain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
    if (-not $Domain) {
        $Domain = $currentDomain
    }

    $childDomain = $Domain -replace '\..*', ''
    $distinguishedName = ($Domain -split '\.') -join ',DC='
    $distinguishedName = "DC=$distinguishedName"

    # Get subjects
    $Subjects = Get-Subjects -Users $Users -Groups $Groups -Domain $Domain -IncludeWellKnown:$OUT

    #Write-Host $Subjects
    if ($Subjects.Count -eq 0) {
        throw "No valid users or groups were provided or found."
    }

    # Set PSDrive
    $psDrive = "AD"
    if ($currentDomain.ToLower() -ne $Domain.ToLower()) {
        New-PSDrive -Name AD2 -PSProvider ActiveDirectory -Server $Domain -Root "//RootDSE/" | Out-Null
        $psDrive = 'AD2'
    }

    IF (!$IN) {
        # Retrieve all AD objects
        try {
            $allObjects = Get-ADObject -LDAPFilter "(|(objectClass=user)(objectClass=computer)(objectClass=group)(objectClass=organizationalUnit))" -SearchBase $distinguishedName -Properties DistinguishedName, name, nTSecurityDescriptor, objectClass
        } catch {
            throw "Failed to retrieve ACLs for the relevant objects of the domain."
        }

        # Split objects into batches
        $batches = for ($i = 0; $i -lt $allObjects.Count; $i += $BatchSize) {
            $allObjects[$i..($i + $BatchSize - 1)]
        }

        $results= @()
        foreach ($batch in $batches) {
            foreach ($object in $batch) {
                #Write-Host $($object | Out-String) 
                # OUT mode: Check what privileges subjects have over the object
                $partialResults = Get-ACLsForObject -Object $object -TargetPermissions $defaultPermissions -OUPermissions $OUPermissions -Domain $Domain -ChildDomain $childDomain -PSDrive $psDrive -Subjects $Subjects -ExtendedChecks $extendedChecks
            }
            if ($partialResults) {$results += $partialResults}
        }
    } else {
            # IN mode: Check what privileges the object has over the subjects
            $results = Get-ACLsForObject -Object $null -TargetPermissions $targetPermissions -OUPermissions $OUPermissions -Domain $Domain -ChildDomain $childDomain -PSDrive $psDrive -Subjects $Subjects
    }

    if ($results) {
        $sumResults = Invoke-SumResults -Results $results
        Show-Results -Results $sumResults
    } else {
        Write-Host "`nNo relevant ACLs found." -ForegroundColor Yellow
    }
    
}

