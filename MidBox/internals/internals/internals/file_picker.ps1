Add-Type -AssemblyName System.Windows.Forms

$picker=[System.Windows.Forms.OpenFileDialog]::new()
$picker.InitialDirectory=[Environment]::GetFolderPath("Desktop")
$picker.Title="Run in $env:USERNAME"
$picker.ShowDialog() | Out-Null

if($picker.FileName){
    Start-Process -WorkingDirectory (Split-Path $picker.FileName -Parent) $picker.FileName
}