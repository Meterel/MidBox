param(
    [switch]$revert
)
$ErrorActionPreference="stop"
trap{
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show($_,$MyInvocation.MyCommand,"OK","Error") | Out-Null
}
. $PSScriptRoot\shared.ps1

$rule=[System.Security.AccessControl.RegistryAccessRule]::new($appcontainer_rule.IdentityReference,$appcontainer_rule.FileSystemRights.ToString(),$appcontainer_rule.InheritanceFlags,$appcontainer_rule.PropagationFlags,$appcontainer_rule.AccessControlType)
foreach($x in (Get-ChildItem -Recurse -Force HKCU:\ | Where-Object Name -NotLike "*\AppContainer*")+(Get-Item HKCU:\) | Resolve-Path | Get-Acl){
    if($true -notin $x.Access.IsInherited){
        if($revert){
            $x.RemoveAccessRuleAll($rule)
        }else{
            $x.SetAccessRule($rule)
        }

        Set-Acl -ErrorAction Continue $x.Path $x
    }
}

$start_menu=[Environment]::GetFolderPath("Desktop")+"\Start Menu.lnk"
$local_start_menu=[Environment]::GetFolderPath("Desktop")+"\Local Start Menu.lnk"
if($revert){
    Remove-Item -ErrorAction SilentlyContinue $start_menu,$local_start_menu
}else{
    create_shortcut ([Environment]::GetFolderPath("CommonStartMenu")+"\Programs") $start_menu
    create_shortcut ([Environment]::GetFolderPath("StartMenu")+"\Programs") $local_start_menu
}

if($revert){
    Add-Type @"
        using System;
        using System.Reflection;
        using System.Runtime.InteropServices;

        public class Win32{
            [DllImport("Userenv.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="DeleteAppContainerProfile")]
            static extern int _DeleteAppContainerProfile(string pszAppContainerName);
            public static void DeleteAppContainerProfile(string pszAppContainerName){
                if(_DeleteAppContainerProfile(pszAppContainerName)!=0) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());
            }
        }
"@

    [Win32]::DeleteAppContainerProfile("Meterel.MidBox.AppContainer")
}