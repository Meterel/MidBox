$version="1.2.0"

$appcontainer_rule=[System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new("S-1-15-2-1388956366-2258462785-1159399181-844480566-995560047-3502612569-1338837068"),"FullControl","ContainerInherit,ObjectInherit","None","Allow")
$group_rule=[System.Security.AccessControl.FileSystemAccessRule]::new((Get-LocalGroup "MidBox sandboxes").SID,"Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership","ContainerInherit,ObjectInherit","None","Deny")
$objects=@(
    #group rule is also applied to read only dirs to avoid subdirs allowing writing
    @("$env:SystemDrive\",             @($group_rule,$appcontainer_rule)),
    @($env:ProgramFiles,               @($group_rule,$appcontainer_rule)),
    @(${env:ProgramFiles(x86)},        @($group_rule,$appcontainer_rule)),
    @($env:ProgramData,                @($group_rule,$appcontainer_rule)),
    @("$env:ProgramData\Microsoft",    @($group_rule,$appcontainer_rule)), #for start menu shortcut
    @("$env:SystemDrive\Users",        @($group_rule,$appcontainer_rule)),
    @($env:PUBLIC,                     @($group_rule,$appcontainer_rule)),
    @("$env:SystemDrive\Users\Default",@($group_rule,$appcontainer_rule))

    #acl changes to some hive keys will corrupt the registry, i've discovered that the hard way. thanks, microsoft!
    #Registry::HKEY_LOCAL_MACHINE\ apparently safe DOESNT RETAIN PERMS
    #Registry::HKEY_CLASSES_ROOT\ WILL CORRUPT REGISTRY
    #Registry::HKEY_CURRENT_USER\ apparently safe
    #Registry::HKEY_CURRENT_CONFIG\ WILL CORRUPT REGISTRY
    #Registry::HKEY_USERS\ apparently safe DOESNT RETAIN PERMS
)

function set_perms{
    param(
        $objects,
        [switch]$remove
    )

    Write-Host "Permission changes can be very slow. Do not interrupt this process because it may leave permissions in a broken state"


    #this is to break objects into pools in witch they're fully separate and paths don't encapsulate eachother
    #even tough acl changes are to paths with acl inheritance disabled, a race condition can occur in witch the perms don't get set
    #this is insanity, why do acls get written in subdirs even tough their inheritance is disabled? and why don't they have a locking mechanism to prevent race conditions????
    #i tought that an fs should be ridden with features that enforce integrity, guess i was wrong
    #as of 25/6/2025 Microsoft's market cap is 3.61 TRILLION WITH A T, and they are still doing ts
    $obj=[System.Collections.ArrayList]::new($objects)
    $pools=[System.Collections.ArrayList]::new() #must be used or else ps flattens loop's output arrays
    while($obj){
        $pool=[System.Collections.ArrayList]::new()

        for($i=0;$i -lt $obj.Count){
            $cc=Convert-Path "$($obj[$i][0])\"

            if($pool | Where-Object {
                $a=Convert-Path "$($_[0])\"
                $cc.StartsWith($a) -or $a.StartsWith($cc)
            }){
                $i++
                continue
            }

            $pool.Add($obj[$i]) | Out-Null
            $obj.RemoveAt($i)
        }

        $pools.Add($pool) | Out-Null
    }


    foreach($pool in $pools){
        $chunks=[Math]::Min([Environment]::ProcessorCount,$pool.Count)
        $chunk_size=$pool.Count/$chunks
        $jobs=for($i=0;$i -lt $chunks){
            $chunk=$pool[($i*$chunk_size)..(++$i*$chunk_size-1)]

            #legacy solution: Start-ThreadJob is powershell 6+ only
            Start-Job {
                $ErrorActionPreference="stop"


                foreach($i in $using:chunk){
                    Write-Host "Setting perms for $($i[0])..."

                    $acl=Get-Acl $i[0]
                    $old_acl=$acl.Access | ForEach-Object {$_ | Out-String}

                    if($using:remove){
                        foreach($x in $i[1]){
                            $acl.RemoveAccessRuleSpecific([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new($x.IdentityReference),$x.FileSystemRights,$x.InheritanceFlags,$x.PropagationFlags,$x.AccessControlType)) #legacy solution: non ThreadJobs don't properly pass complex data
                        }
                    }else{
                        foreach($x in $i[1]){
                            $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new($x.IdentityReference),$x.FileSystemRights,$x.InheritanceFlags,$x.PropagationFlags,$x.AccessControlType)) #legacy solution: non ThreadJobs don't properly pass complex data
                        }
                    }

                    if(Compare-Object ($acl.Access | ForEach-Object {$_ | Out-String}) $old_acl){
                        Set-Acl $i[0] $acl
                        Write-Host "Perms set for $($i[0])"
                    }else{
                        Write-Host "Perms already set for $($i[0])"
                    }
                }
            }
        }

        Receive-Job -AutoRemoveJob -Wait -ErrorAction Continue $jobs #must have -ErrorAction Continue or else perms will be corrupted if Set-Acl is halted
        if($jobs.State -ne "Completed"){
            throw "Some permission changes have failed"
        }
    }
}


function create_shortcut{
    param(
        $source,
        $destination,
        $arg,
        [switch]$admin
    )

    $shortcut=(New-Object -ComObject "WScript.Shell").CreateShortcut($destination)
    $shortcut.TargetPath=$source
    $shortcut.Arguments=$arg
    $shortcut.Save()

    if($admin){
        #hack from https://www.reddit.com/r/PowerShell/comments/7xa4sk/programmatically_create_shortcuts_w_run_as_admin
        #there is no other way. thanks again, microsoft!
        $f=[System.IO.FileStream]::new($destination,"Open")
        $f.Position=21
        $f.WriteByte(32)
        $f.Close()
    }
}