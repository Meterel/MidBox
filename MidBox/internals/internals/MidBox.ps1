param(
    $RunIn
)
$ErrorActionPreference="stop"
trap{
    Write-Error -ErrorAction Continue $_
    Pause
}
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    Start-Process powershell -Verb RunAs ("-executionpolicy","unrestricted","-file","""$PSCommandPath"""+($PSBoundParameters.GetEnumerator() | ForEach-Object {"-$($_.Key)",$_.Value}))
    exit
}

Add-Type -AssemblyName System.Web

function get_sandbox{
    param(
        $sandbox=(Read-Host "Sandbox name?")
    )

    try{
        ((Get-LocalGroupMember "MidBox sandboxes" $sandbox) -split "\\")[1]
    }catch{
        throw "Sandbox $sandbox doesn't exist"
    }
}

function run_in{
    param(
        $user,
        $program,
        $arg,
        [switch]$Wait,
        [switch]$PassThru
    )

    $pass=ConvertTo-SecureString -AsPlainText -Force ([System.Web.Security.Membership]::GeneratePassword(24,0)) #16 bytes of entropy on base64
    Set-LocalUser $user -Password $pass

    $pi=[System.Diagnostics.Process]::Start((New-Object System.Diagnostics.ProcessStartInfo $program,$arg -Property @{
        CreateNoWindow=$true; #reduce attack surface for example from a custom console and it's config
        UserName=$user;
        Password=$pass;
        LoadUserProfile=$true;
        UseShellExecute=$false #legacy solution: is true on powershell 5 and must be false if run as user
    }))

    Set-LocalUser $user -Password ([securestring]::new())

    if($Wait){
        $pi.WaitForExit()
    }
    if($PassThru){
        $pi
    }
}

if($RunIn){
    run_in (get_sandbox $RunIn) powershell "-executionpolicy","unrestricted","-NoProfile","-NonInteractive","-file","""$PSScriptRoot\internals\run_in_appcontainer.ps1""","""powershell -executionpolicy unrestricted -NonInteractive -windowstyle hidden -file \""$PSScriptRoot\internals\file_picker.ps1\"""""
    exit
}


. $PSScriptRoot\internals\shared.ps1
Add-Type @"
    using System;
    using System.Reflection;
    using System.Runtime.InteropServices;

    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    public struct WTS_SESSION_INFOW{
        public uint SessionId;
        public string pWinStationName;
        public int State;
    }

    public class Win32{
        [DllImport("Wtsapi32.dll")]
        static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("Wtsapi32.dll",EntryPoint="WTSEnumerateSessionsW",SetLastError=true)]
        static extern bool _WTSEnumerateSessionsW(IntPtr hServer,uint Reserved,uint Version,out IntPtr ppSessionInfo,out uint pCount);
        public static WTS_SESSION_INFOW[] WTSEnumerateSessions(IntPtr hServer,uint Reserved,uint Version){
            IntPtr ptr;
            uint count;
            if(!_WTSEnumerateSessionsW(hServer,Reserved,Version,out ptr,out count)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());

            var r=new WTS_SESSION_INFOW[count];
            for(int i=0;i<count;i++) r[i]=Marshal.PtrToStructure<WTS_SESSION_INFOW>(ptr+i*Marshal.SizeOf(typeof(WTS_SESSION_INFOW)));

            WTSFreeMemory(ptr);
            return r;
        }

        [DllImport("Wtsapi32.dll",EntryPoint="WTSQuerySessionInformationW",SetLastError=true)]
        static extern bool _WTSQuerySessionInformationW(IntPtr hServer,uint SessionId,int WTSInfoClass,out IntPtr ppBuffer,out uint pBytesReturned);
        public static string WTSQuerySessionInformation(IntPtr hServer,uint SessionId,int WTSInfoClass){
            IntPtr x;
            uint y;
            if(!_WTSQuerySessionInformationW(hServer,SessionId,WTSInfoClass,out x,out y)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());

            var r=Marshal.PtrToStringUni(x);

            WTSFreeMemory(x);
            return r;
        }

        [DllImport("Wtsapi32.dll",EntryPoint="WTSLogoffSession",SetLastError=true)]
        static extern bool _WTSLogoffSession(IntPtr hServer,uint SessionId,bool bWait);
        public static void WTSLogoffSession(IntPtr hServer,uint SessionId,bool bWait){
            if(!_WTSLogoffSession(hServer,SessionId,bWait)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());
        }


        [DllImport("Userenv.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="DeleteProfileW")]
        static extern bool _DeleteProfileW(string lpSidString,IntPtr lpProfilePath,IntPtr lpComputerName);
        public static void DeleteProfile(string lpSidString){
            if(!_DeleteProfileW(lpSidString,(IntPtr)0,(IntPtr)0)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());
        }
    }
"@

function init_sandbox{
    param(
        $sandbox,
        [switch]$revert
    )

    $arg="-executionpolicy","unrestricted","-NoProfile","-NonInteractive","-file","""$PSScriptRoot\internals\init_sandbox.ps1"""
    if($revert){
        $arg+="-revert"
    }

    Write-Host "Initializing $sandbox..."
    if((run_in $sandbox powershell $arg -Wait -PassThru).ExitCode){
        throw "Initialization of $sandbox failed"
    }

    $userprofile=(Get-CimInstance Win32_UserProfile | Where-Object SID -EQ (Get-LocalUser $sandbox).SID).LocalPath #userprofile isn't always in "$env:SystemDrive\Users\$user"
    $acl=Get-Acl $userprofile
    if($revert){
        $acl.RemoveAccessRuleAll($appcontainer_rule)
    }else{
        $acl.SetAccessRule($appcontainer_rule)
    }
    Set-Acl $userprofile $acl
}

function stop_user{
    param(
        $user,
        [switch]$PassThru
    )

    foreach($x in [Win32]::WTSEnumerateSessions(0,0,1)){
        if([Win32]::WTSQuerySessionInformation(0,$x.SessionId,5) -eq $user){
            Write-Host "Logging off $user..."
            [Win32]::WTSLogoffSession(0,$x.SessionId,$true)
            break
        }
    }

    Get-Process -IncludeUserName | Where-Object UserName -EQ "$env:COMPUTERNAME\$user" | Stop-Process -Force -PassThru:$PassThru
}


for(){
    Clear-Host
    $sandboxes=Get-LocalGroupMember "MidBox sandboxes"
    Write-Host @"
MidBox v$version (doesn't update automatically) | Made by Meterel at https://github.com/Meterel/MidBox

Sandboxes ($($sandboxes.Count)):
"@
    Write-Host (($sandboxes | ForEach-Object {$_.Name.Split("\")[1]}) -join ", ")

    $s=Read-Host @"

1.Run in sandbox
2.Enable sandbox interactive login without AppContainer (UNSAFE, more compatibility)
3.Disable sandbox interactive login
4.Run in sandbox without AppContainer (DANGEROUS!, same compatibility as interactive login)
5.Stop sandbox
6.Stop all sandboxes
7.Create sandbox
8.Set sandbox capabilities
9.Rename sandbox
10.Remove sandbox
11.Remove contents of sandbox
12.Convert sandbox to standard user
13.Convert user to sandbox
14.Initialize path for setting permissions
15.Deinitialize path for setting permissions

"@
    Write-Host ""

    try{
        switch($s){
            "1"{
                run_in (get_sandbox) powershell "-executionpolicy","unrestricted","-NoProfile","-NonInteractive","-file","""$PSScriptRoot\internals\run_in_appcontainer.ps1""","""powershell -executionpolicy unrestricted -NonInteractive -windowstyle hidden -file \""$PSScriptRoot\internals\file_picker.ps1\"""""
                exit
            }

            "2"{
                $user=get_sandbox

                if((Read-Host @"

WARNING! This will allow logging into the sandbox without AppContainer as a standard user by adding it to the Users group, this meaning that:

* Files out of the sandbox's user directory may be writable
* External partitions will be completely accessible
* Internet, cameras and microphones etc. will be accessible
* It can ask for running as administrator, if granted it'll be able to bypass all restrictions

Sandbox escape might be possible by poisoning files like executables in external partitions that the user may run therefore manually blocking external partitions with permissions is heavily recommended.
Its recommended to use this option in a sandbox you trust with files that you trust.

Write 'YES' to continue
"@) -ne "YES"){
                    break
                }

                Add-LocalGroupMember Users $user

                Write-Host "Enabled interactive login for $user"
                Pause
                break
            }

            "3"{
                $user=get_sandbox

                Remove-LocalGroupMember Users $user

                Write-Host "Disabled interactive login for $user"
                Pause
                break
            }

            "4"{
                $user=get_sandbox

                if((Read-Host @"

WARNING! AppContainer is a crucial step in the sandboxing pipeline, without AppContainer:

* Files out of the sandbox's user directory may be writable
* External partitions will be completely accessible
* Internet, clipboard, cameras and microphones etc. will be accessible
* Almost all processes will be accessible and could be killed, sent input/message to their windows etc.
* It can ask for running as administrator, if granted it'll be able to bypass all restrictions

SANDBOX ESCAPE IS ESSENTIALLY GUARANTEED TO BE POSSIBLE by sending the right input/message to the right window at the right time or by poisoning files like executables in external partitions that the user may run.
Manually blocking external partitions with permissions is heavily recommended.
Only use this option in a sandbox you trust with files that you trust.

Its heavily recommended to use the safer but still unsafe interactive login mode instead of this option.

Write 'YES' to continue
"@) -ne "YES"){
                    break
                }

                run_in $user powershell "-executionpolicy","unrestricted","-NoProfile","-NonInteractive","-file","""$PSScriptRoot\internals\file_picker.ps1"""
                exit
            }

            "5"{
                $procs=stop_user (get_sandbox) -PassThru
                Write-Output $procs

                Write-Host "$($procs.Count) processes terminated"
                Pause
                break
            }

            "6"{
                $users=(Get-LocalGroupMember "MidBox sandboxes").Name
                #Get-Process's UserName and $users can be null and $null -in $null is true
                $procs=if($users){
                    [Win32]::WTSEnumerateSessions(0,0,1) | ForEach-Object {
                        $user=[Win32]::WTSQuerySessionInformation(0,$_.SessionId,5)
                        if("$env:COMPUTERNAME\$user" -in $users){
                            Write-Host "Logging off $user..."
                            [Win32]::WTSLogoffSession(0,$_.SessionId,$true)
                        }
                    }

                    Get-Process -IncludeUserName | Where-Object UserName -In $users | Stop-Process -Force -PassThru
                }
                Write-Output $procs

                Write-Host "$($procs.Count) processes terminated"
                Pause
                break
            }

            "7"{
                $user=Read-Host "Sandbox name?"
                New-LocalUser $user -NoPassword | Add-LocalGroupMember "MidBox sandboxes"
                Set-LocalUser $user -PasswordNeverExpires $true

                init_sandbox $user
                create_shortcut -admin "powershell" ([Environment]::GetFolderPath("Desktop")+"\Run in $user.lnk") "-executionpolicy unrestricted -file ""$env:ProgramFiles\MidBox\program\MidBox.ps1"" -RunIn ""$user"""

                Write-Host "Sandbox $user created"
                Pause
                break
            }

            "8"{
                $path="$env:ProgramFiles\MidBox\data\sandboxes\$(get_sandbox)\capabilities.txt"

                if(-not (Test-Path $path)){
                    @"
# You can set here AppContainer capabilities
# A list of possible capabilities can be found here: https://learn.microsoft.com/en-us/windows/uwp/packaging/app-capability-declarations
# Try uncommenting some of the capabilities below to grant them to the sandbox by removing the "#" at the start of their line

#internetClient # Allows internet access
#internetClientServer # Allows hosting an internet server
#privateNetworkClientServer # Allows local internet access, like to a printer connected to your Wi-Fi
"@ | Out-File (New-Item -Force $path)
                }
                Invoke-Item $path

                break
            }

            "9"{
                $user=get_sandbox

                $new_name=Read-Host "New name?"
                stop_user $user
                Rename-LocalUser $user $new_name
                Rename-Item -ErrorAction SilentlyContinue $env:ProgramFiles\MidBox\data\sandboxes\$user $new_name
                try{
                    Remove-Item ([Environment]::GetFolderPath("Desktop")+"\Run in $user.lnk")
                    create_shortcut -admin "powershell" ([Environment]::GetFolderPath("Desktop")+"\Run in $new_name.lnk") "-executionpolicy unrestricted -file ""$env:ProgramFiles\MidBox\program\MidBox.ps1"" -RunIn ""$new_name"""
                }catch{}
                $sid=(Get-LocalUser $new_name).SID
                Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" ProfileImagePath (Rename-Item -PassThru (Get-CimInstance Win32_UserProfile | Where-Object SID -EQ $sid).LocalPath $new_name).Target #FullName has a \ at the end

                Write-Host "Sandbox $user renamed to $new_name"
                Pause
                break
            }

            "10"{
                $user=get_sandbox

                if((Read-Host "Are you sure to IRREVERSIBLY DELETE $user and its contents? Write 'YES' to continue") -ne "YES"){
                    break
                }

                stop_user $user
                Remove-Item -ErrorAction SilentlyContinue -Recurse $env:ProgramFiles\MidBox\data\sandboxes\$user
                Remove-Item -ErrorAction SilentlyContinue ([Environment]::GetFolderPath("Desktop")+"\Run in $user.lnk")
                [Win32]::DeleteProfile((Get-LocalUser $user).SID) #Remove-LocalUser leaves USERPROFILE dir and registry entries, there is no proper way for this other than trough Win32, this is insane
                Remove-LocalUser $user

                Write-Host "Sandbox $user deleted"
                Pause
                break
            }

            "11"{
                $user=get_sandbox

                if((Read-Host "Are you sure to IRREVERSIBLY DELETE the contents of $($user)? Write 'YES' to continue") -ne "YES"){
                    break
                }

                stop_user $user
                [Win32]::DeleteProfile((Get-LocalUser $user).SID)
                init_sandbox $user

                Write-Host "Contents of $user deleted"
                Pause
                break
            }

            "12"{
                $user=get_sandbox

                if((Read-Host "Are you sure to REMOVE ALL RESTRICTIONS of $user converting it to a standard user? Write 'YES' to continue") -ne "YES"){
                    break
                }

                init_sandbox $user -revert
                Remove-Item -ErrorAction SilentlyContinue -Recurse $env:ProgramFiles\MidBox\data\sandboxes\$user
                Remove-Item -ErrorAction SilentlyContinue ([Environment]::GetFolderPath("Desktop")+"\Run in $user.lnk")
                Remove-LocalGroupMember "MidBox sandboxes" $user
                Add-LocalGroupMember -ErrorAction SilentlyContinue Users $user

                Write-Host "Sandbox $user converted to a standard user"
                Pause
                break
            }

            "13"{
                $user=Read-Host "Username?" | Get-LocalUser
                if($user.Name -eq $env:USERNAME){
                    throw "The current logged in user can't be converted"
                }
                if(-not $user.Enabled){
                    throw "Disabled users can't be converted"
                }
                if(Get-LocalGroupMember -ErrorAction SilentlyContinue "MidBox sandboxes" $user){
                    throw "$user is already a sandbox"
                }

                $groups=Get-LocalGroup | Where-Object {$_.Name -notin @("Users","Administrators") -and "$env:COMPUTERNAME\$user" -in (Get-LocalGroupMember $_).Name}
                if($groups){
                    $x=Read-Host @"
WARNING! The user is in the following groups: $($groups -join ", ")
They may grant the user extra priviledges, if unsure, remove them
Remove or keep the user in the groups? (remove/keep)
"@
                    if($x -eq "keep"){
                        $groups=@()
                    }elseif($x -ne "remove"){
                        break
                    }
                }

                Remove-LocalGroupMember -ErrorAction SilentlyContinue Users $user #-ErrorAction SilentlyContinue because the user created at windows install isn't in Users
                Remove-LocalGroupMember -ErrorAction SilentlyContinue Administrators $user
                $groups | ForEach-Object {Remove-LocalGroupMember $_ $user}
                Add-LocalGroupMember "MidBox sandboxes" $user
                init_sandbox $user
                create_shortcut -admin "powershell" ([Environment]::GetFolderPath("Desktop")+"\Run in $user.lnk") "-executionpolicy unrestricted -file ""$env:ProgramFiles\MidBox\program\MidBox.ps1"" -RunIn ""$user"""

                Write-Host "User $user converted to a sandbox"
                Pause
                break
            }

            "14"{
                Write-Host @"
This is meant to be used mainly on partitions or on paths with ACLs that have inheritance disabled
After initialization, you can grant it access to sandboxes either by modifying the initialized permissions or by adding permissions in subdirectories
"@

                $path=Read-Host "Path?" | Convert-Path
                if($objects | Where-Object {$_[0] -eq $path}){
                    throw "Path $path can't be initialized because it's managed by MidBox"
                }

                Write-Host "Initializing... this can be very slow. Do not interrupt or permissions will corrupt"
                $acl=Get-Acl $path
                $acl.SetAccessRule($appcontainer_rule)
                $acl.SetAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new((Get-LocalGroup "MidBox sandboxes").SID,"FullControl","ContainerInherit,ObjectInherit","None","Deny"))
                Set-Acl $path $acl

                Write-Host "Path $path initialized"
                Pause
                break
            }

            "15"{
                Write-Host "This won't remove permissions you've set and you'll have to remove them manually"

                $path=Read-Host "Path?" | Convert-Path
                if($objects | Where-Object {$_[0] -eq $path}){
                    throw "Path $path can't be deinitialized because it's managed by MidBox"
                }

                Write-Host "Deinitializing... this can be very slow. Do not interrupt or permissions will corrupt"
                $acl=Get-Acl $path
                $acl.RemoveAccessRuleAll($appcontainer_rule)
                $acl.RemoveAccessRuleAll($group_rule)
                Set-Acl $path $acl

                Write-Host "Path $path deinitialized"
                Pause
                break
            }
        }
    }catch{
        Write-Error -ErrorAction Continue $_
        Pause
    }
}