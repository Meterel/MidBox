$ErrorActionPreference="stop"
trap{
    Write-Error -ErrorAction Continue $_
    Pause
}

if((Get-LocalGroupMember "MidBox sandboxes") -and (Read-Host "WARNING! There still exist sandboxes, uninstalling MidBox will NOT remove them. Write 'YES' to continue") -ne "YES"){
    exit
}


$users=(Get-LocalGroupMember "MidBox sandboxes").Name #user may have deleted sandboxes when warned
#Get-Process's UserName and $users can be null and $null -in $null is true
if($users){
    Remove-LocalGroupMember -ErrorAction SilentlyContinue Users $users

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
                if(!_WTSEnumerateSessionsW(hServer,Reserved,Version,out ptr,out count)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());

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
                if(!_WTSQuerySessionInformationW(hServer,SessionId,WTSInfoClass,out x,out y)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());

                var r=Marshal.PtrToStringUni(x);

                WTSFreeMemory(x);
                return r;
            }

            [DllImport("Wtsapi32.dll",EntryPoint="WTSLogoffSession",SetLastError=true)]
            static extern bool _WTSLogoffSession(IntPtr hServer,uint SessionId,bool bWait);
            public static void WTSLogoffSession(IntPtr hServer,uint SessionId,bool bWait){
                if(!_WTSLogoffSession(hServer,SessionId,bWait)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());
            }
        }
"@

    [Win32]::WTSEnumerateSessions(0,0,1) | ForEach-Object {
        $user=[Win32]::WTSQuerySessionInformation(0,$_.SessionId,5)
        if("$env:COMPUTERNAME\$user" -in $users){
            Write-Host "Logging off $user..."
            [Win32]::WTSLogoffSession(0,$_.SessionId,$true)
        }
    }

    Get-Process -IncludeUserName | Where-Object UserName -In $users | Stop-Process -Force
}

Remove-Item -ErrorAction SilentlyContinue ([Environment]::GetFolderPath("Desktop")+"\MidBox.lnk")
Remove-Item -ErrorAction Continue ([Environment]::GetFolderPath("CommonStartMenu")+"\Programs\MidBox.lnk")

. $PSScriptRoot\shared.ps1
set_perms $objects -remove

Remove-Item -Recurse $env:ProgramFiles\MidBox\program
if(-not $users){
    Remove-LocalGroup "MidBox sandboxes"
    Remove-Item -Recurse $env:ProgramFiles\MidBox
}

Remove-Item -Recurse HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MidBox