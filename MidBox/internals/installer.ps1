$ErrorActionPreference="stop"
trap{
    Write-Error -ErrorAction Continue $_
    Pause
}
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    Start-Process powershell -Verb RunAs ("-executionpolicy","unrestricted","-file","""$PSCommandPath"""+($PSBoundParameters.GetEnumerator() | ForEach-Object {"-$($_.Key)",$_.Value}))
    exit
}


Remove-Item -ErrorAction SilentlyContinue -Recurse $env:ProgramFiles\MidBox\program
Copy-Item -Recurse $PSScriptRoot\internals $env:ProgramFiles\MidBox\program

$reg_uninst="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MidBox"
Remove-Item -ErrorAction SilentlyContinue -Recurse $reg_uninst
New-Item $reg_uninst | Out-Null
Set-ItemProperty $reg_uninst UninstallString "powershell -executionpolicy unrestricted -file ""$env:ProgramFiles\MidBox\program\internals\uninstall.ps1"""
Set-ItemProperty $reg_uninst DisplayName MidBox
Set-ItemProperty $reg_uninst Publisher Meterel

New-LocalGroup -ErrorAction SilentlyContinue "MidBox sandboxes" | Out-Null

. $PSScriptRoot\internals\internals\shared.ps1
set_perms $objects

create_shortcut -admin "powershell" ([Environment]::GetFolderPath("Desktop")+"\MidBox.lnk") "-executionpolicy unrestricted -file ""$env:ProgramFiles\MidBox\program\MidBox.ps1"""
create_shortcut -admin "powershell" ([Environment]::GetFolderPath("CommonStartMenu")+"\Programs\MidBox.lnk") "-executionpolicy unrestricted -file ""$env:ProgramFiles\MidBox\program\MidBox.ps1"""


Write-Host ""
Write-Host "Installed successfully"
Pause