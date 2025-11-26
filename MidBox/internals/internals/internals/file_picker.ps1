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
    Start-Process -WorkingDirectory (Split-Path $picker.FileName -Parent) $picker.FileName
}