$ErrorActionPreference="stop"
Add-Type -AssemblyName System.Windows.Forms
trap{
    [System.Windows.Forms.MessageBox]::Show($_,$MyInvocation.MyCommand,"OK","Error") | Out-Null
}


$picker=[System.Windows.Forms.OpenFileDialog]::new()
$picker.InitialDirectory=[Environment]::GetFolderPath("Desktop")
$picker.Title="Run in $env:USERNAME"
$picker.ShowDialog() | Out-Null

if($picker.FileName){
    (New-Object -ComObject "Shell.Application").ShellExecute($picker.FileName,"",(Split-Path $picker.FileName -Parent)) #same behavior as explorer, prompting when a file is network blocked instead of throwing
}