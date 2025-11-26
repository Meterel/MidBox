param(
    $cmd
)
$ErrorActionPreference="stop"
trap{
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show($_,$MyInvocation.MyCommand,"OK","Error") | Out-Null
}

#according to https://learn.microsoft.com/en-us/dotnet/standard/native-interop/type-marshalling win32's BOOL (4 bytes) can be marshalled into a bool (1 byte)
Add-Type @"
    using System;
    using System.Reflection;
    using System.Diagnostics;
    using System.Security.Principal;
    using System.Security.AccessControl;
    using System.Runtime.InteropServices;

    public struct ACL{
        public byte AclRevision;
        public byte Sbz1;
        public ushort AclSize;
        public ushort AceCount;
        public ushort Sbz2;
    }

    [StructLayout(LayoutKind.Sequential)] //GCHandle is used to get its address
    public struct SID_AND_ATTRIBUTES{
        public IntPtr Sid;
        public uint Attributes;
    }

    public struct SECURITY_CAPABILITIES{
        public IntPtr AppContainerSid;
        public IntPtr Capabilities; //if type is SID_AND_ATTRIBUTES[] CreateProcessAsUser throws 87
        public uint CapabilityCount;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    public struct STARTUPINFOW{
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    public struct STARTUPINFOEX{
        public STARTUPINFOW StartupInfo;
        public IntPtr lpAttributeList;
    }

    public struct PROCESS_INFORMATION{
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    public struct Wow64Process2{
        public ushort ProcessMachine;
        public ushort NativeMachine;
    }

    public class Win32{
        [DllImport("Userenv.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="DeleteAppContainerProfile")]
        static extern int _DeleteAppContainerProfile(string pszAppContainerName);
        public static void DeleteAppContainerProfile(string pszAppContainerName){
            if(_DeleteAppContainerProfile(pszAppContainerName)!=0) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());
        }

        [DllImport("Userenv.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="CreateAppContainerProfile")]
        static extern int _CreateAppContainerProfile(string pszAppContainerName,string pszDisplayName,string pszDescription,IntPtr pCapabilities,uint dwCapabilityCount,out IntPtr ppSidAppContainerSid);
        public static IntPtr CreateAppContainerProfile(string pszAppContainerName,string pszDisplayName,string pszDescription,IntPtr pCapabilities,uint dwCapabilityCount){
            IntPtr x;
            if(_CreateAppContainerProfile(pszAppContainerName,pszDisplayName,pszDescription,pCapabilities,dwCapabilityCount,out x)!=0) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());
            return x;
        }


        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("Advapi32.dll",SetLastError=true,EntryPoint="OpenProcessToken")]
        static extern bool _OpenProcessToken(IntPtr ProcessHandle,uint DesiredAccess,out IntPtr TokenHandle);
        public static IntPtr OpenProcessToken(IntPtr ProcessHandle,uint DesiredAccess){
            IntPtr x;
            if(!_OpenProcessToken(ProcessHandle,DesiredAccess,out x)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());
            return x;
        }

        [DllImport("Advapi32.dll",SetLastError=true,EntryPoint="CreateRestrictedToken")]
        static extern bool _CreateRestrictedToken(IntPtr ExistingTokenHandle,uint Flags,uint DisableSidCount,IntPtr SidsToDisable,uint DeletePrivilegeCount,IntPtr PrivilegesToDelete,uint RestrictedSidCount,IntPtr SidsToRestrict,out IntPtr NewTokenHandle);
        public static IntPtr CreateRestrictedToken(IntPtr ExistingTokenHandle,uint Flags,uint DisableSidCount,IntPtr SidsToDisable,uint DeletePrivilegeCount,IntPtr PrivilegesToDelete,uint RestrictedSidCount,IntPtr SidsToRestrict){
            IntPtr x;
            if(!_CreateRestrictedToken(ExistingTokenHandle,Flags,DisableSidCount,SidsToDisable,DeletePrivilegeCount,PrivilegesToDelete,RestrictedSidCount,SidsToRestrict,out x)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());
            return x;
        }

        [DllImport("Advapi32.dll",SetLastError=true,EntryPoint="GetTokenInformation")]
        static extern bool _GetTokenInformation(IntPtr TokenHandle,int TokenInformationClass,IntPtr TokenInformation,uint TokenInformationLength,out uint ReturnLength);
        public static uint GetTokenInformationSize(IntPtr TokenHandle,int TokenInformationClass){
            uint x;
            _GetTokenInformation(TokenHandle,TokenInformationClass,(IntPtr)0,0,out x);
            return x;
        }

        public static void GetTokenInformation(IntPtr TokenHandle,int TokenInformationClass,IntPtr TokenInformation,uint TokenInformationLength){
            uint x;
            if(!_GetTokenInformation(TokenHandle,TokenInformationClass,TokenInformation,TokenInformationLength,out x)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());
        }

        [DllImport("Advapi32.dll",SetLastError=true,EntryPoint="SetTokenInformation")]
        static extern bool _SetTokenInformation(IntPtr TokenHandle,int TokenInformationClass,IntPtr TokenInformation,uint TokenInformationLength);
        public static void SetTokenInformation(IntPtr TokenHandle,int TokenInformationClass,IntPtr TokenInformation,uint TokenInformationLength){
            if(!_SetTokenInformation(TokenHandle,TokenInformationClass,TokenInformation,TokenInformationLength)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());
        }


        [DllImport("kernelbase.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="DeriveCapabilitySidsFromName")]
        static extern bool _DeriveCapabilitySidsFromName(string CapName,ref IntPtr CapabilityGroupSids,out uint CapabilityGroupSidCount,ref IntPtr CapabilitySids,out uint CapabilitySidCount);
        public static SID_AND_ATTRIBUTES DeriveCapabilitySidsFromName(string CapName){
            var groupSids=Marshal.AllocHGlobal(IntPtr.Size);
            uint groupSidsCount;
            var sids=Marshal.AllocHGlobal(IntPtr.Size);
            uint sidsCount;
            if(!_DeriveCapabilitySidsFromName(CapName,ref groupSids,out groupSidsCount,ref sids,out sidsCount)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());

            return new SID_AND_ATTRIBUTES{Sid=Marshal.ReadIntPtr(sids),Attributes=4 /* flag SE_GROUP_ENABLED */};
        }

        [DllImport("Kernel32.dll",SetLastError=true,EntryPoint="InitializeProcThreadAttributeList")]
        static extern bool _InitializeProcThreadAttributeList(IntPtr lpAttributeList,uint dwAttributeCount,uint dwFlags,ref UIntPtr lpSize);
        public static UIntPtr InitializeProcThreadAttributeListSize(uint dwAttributeCount){
            UIntPtr x=(UIntPtr)0;
            _InitializeProcThreadAttributeList((IntPtr)0,dwAttributeCount,0,ref x);
            return x;
        }

        public static void InitializeProcThreadAttributeList(IntPtr lpAttributeList,uint dwAttributeCount,uint dwFlags,UIntPtr lpSize){
            if(!_InitializeProcThreadAttributeList(lpAttributeList,dwAttributeCount,dwFlags,ref lpSize)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());
        }

        [DllImport("Kernel32.dll",SetLastError=true,EntryPoint="UpdateProcThreadAttribute")]
        static extern bool _UpdateProcThreadAttribute(IntPtr lpAttributeList,uint dwFlags,UIntPtr Attribute,ref SECURITY_CAPABILITIES lpValue,UIntPtr cbSize,IntPtr lpPreviousValue,IntPtr lpReturnSize);
        public static void UpdateProcThreadAttribute(IntPtr lpAttributeList,uint dwFlags,UIntPtr Attribute,SECURITY_CAPABILITIES lpValue,UIntPtr cbSize,IntPtr lpPreviousValue,IntPtr lpReturnSize){
            if(!_UpdateProcThreadAttribute(lpAttributeList,dwFlags,Attribute,ref lpValue,cbSize,lpPreviousValue,lpReturnSize)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());
        }

        [DllImport("Advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="CreateProcessAsUserW")]
        static extern bool _CreateProcessAsUserW(IntPtr hToken,IntPtr lpApplicationName,string lpCommandLine,IntPtr lpProcessAttributes,IntPtr lpThreadAttributes,int bInheritHandles,uint dwCreationFlags,IntPtr lpEnvironment,IntPtr lpCurrentDirectory,ref STARTUPINFOEX lpStartupInfo,out PROCESS_INFORMATION lpProcessInformation);
        public static PROCESS_INFORMATION CreateProcessAsUser(IntPtr hToken,IntPtr lpApplicationName,string lpCommandLine,IntPtr lpProcessAttributes,IntPtr lpThreadAttributes,int bInheritHandles,uint dwCreationFlags,IntPtr lpEnvironment,IntPtr lpCurrentDirectory,STARTUPINFOEX lpStartupInfo){
            PROCESS_INFORMATION x;
            if(!_CreateProcessAsUserW(hToken,lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,lpCurrentDirectory,ref lpStartupInfo,out x)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());
            return x;
        }

        [DllImport("Kernel32.dll",SetLastError=true,EntryPoint="IsWow64Process2")]
        static extern bool _IsWow64Process2(IntPtr hProcess,out ushort pProcessMachine,out ushort pNativeMachine);
        public static Wow64Process2 IsWow64Process2(IntPtr hProcess){
            Wow64Process2 x;
            if(!_IsWow64Process2(hProcess,out x.ProcessMachine,out x.NativeMachine)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());
            return x;
        }

        [DllImport("Kernel32.dll",SetLastError=true,EntryPoint="ResumeThread")]
        static extern uint _ResumeThread(IntPtr hThread);
        public static uint ResumeThread(IntPtr hThread){
            var x=_ResumeThread(hThread);
            if((int)x==-1) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error().ToString());
            return x;
        }
    }

    public class Helper{
        //done in c# because in powershell CreateProcessAsUser returned an error
        public static void runInAppcontainer(IntPtr token,IntPtr appcontainerSid,SID_AND_ATTRIBUTES[] capabilities,string cmd){
            //removes the ace that grants access to the logon session, thus achieving sandbox to sandbox runtime isolation even tough they use the same appcontainer sid
            var tokenInfoSize=Win32.GetTokenInformationSize(token,6 /* flag TokenDefaultDacl */);
            var tokenInfo=Marshal.AllocHGlobal((int)tokenInfoSize);
            Win32.GetTokenInformation(token,6 /* flag TokenDefaultDacl */,tokenInfo,tokenInfoSize);

            var tokenAclPtr=Marshal.ReadIntPtr(tokenInfo);
            var tokenAclData=new byte[Marshal.PtrToStructure<ACL>(tokenAclPtr).AclSize];
            Marshal.Copy(tokenAclPtr,tokenAclData,0,tokenAclData.Length);
            var tokenAcl=new DiscretionaryAcl(false,false,new RawAcl(tokenAclData,0)); //IsContainer doesn't change its binary form

            foreach(CommonAce i in tokenAcl)
                if(i.SecurityIdentifier.IsWellKnown(WellKnownSidType.LogonIdsSid)){
                    tokenAcl.Purge(i.SecurityIdentifier);
                    //tokenAcl.AddAccess((AccessControlType)i.AceType,new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null),i.AccessMask,i.InheritanceFlags,i.PropagationFlags); access can only be granted back to the initiator by knowing its explicit sid
                    break;
                }

            tokenAclData=new byte[tokenAcl.BinaryLength];
            tokenAcl.GetBinaryForm(tokenAclData,0);

            tokenInfoSize=(uint)(tokenAclData.Length+IntPtr.Size);
            tokenInfo=Marshal.AllocHGlobal((int)tokenInfoSize);
            Marshal.WriteIntPtr(tokenInfo,tokenInfo+IntPtr.Size);
            Marshal.Copy(tokenAclData,0,tokenInfo+IntPtr.Size,tokenAclData.Length);

            Win32.SetTokenInformation(token,6 /* flag TokenDefaultDacl */,tokenInfo,tokenInfoSize);


            var si=new STARTUPINFOEX();
            si.StartupInfo.cb=(uint)Marshal.SizeOf(si);

            var sc=new SECURITY_CAPABILITIES();
            sc.AppContainerSid=appcontainerSid;
            if(capabilities!=null){
                sc.Capabilities=GCHandle.Alloc(capabilities,GCHandleType.Pinned).AddrOfPinnedObject();
                sc.CapabilityCount=(uint)capabilities.Length;
            }

            var attributeListSize=Win32.InitializeProcThreadAttributeListSize(1);
            si.lpAttributeList=Marshal.AllocHGlobal((int)attributeListSize);
            Win32.InitializeProcThreadAttributeList(si.lpAttributeList,1,0,attributeListSize);
            Win32.UpdateProcThreadAttribute(si.lpAttributeList,0,(UIntPtr)131081 /* flag PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES */,sc,(UIntPtr)Marshal.SizeOf(sc),(IntPtr)0,(IntPtr)0);

            var pi=Win32.CreateProcessAsUser(token,(IntPtr)0,"\"$($PSScriptRoot.Replace("\","\\"))\\post_appcontainer.bat\" && "+cmd,(IntPtr)0,(IntPtr)0,0,16 | 524288 | 4 /* flags CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED */,(IntPtr)0,(IntPtr)0,si);
            var arch=Win32.IsWow64Process2(pi.hProcess);
            Process.Start("$($PSScriptRoot.Replace("\","\\"))\\dll\\injector"+(arch.ProcessMachine==0 /* flag IMAGE_FILE_MACHINE_UNKNOWN */ && arch.NativeMachine!=332 /* flag IMAGE_FILE_MACHINE_I386 */ && arch.NativeMachine!=448 /* flag IMAGE_FILE_MACHINE_ARM */ ? "64" : "32")+".exe",pi.dwProcessId.ToString()).WaitForExit();
            Win32.ResumeThread(pi.hThread);
        }
    }
"@


[Win32]::DeleteAppContainerProfile("Meterel.MidBox.AppContainer") #appcontainer gets recreated every time to avoid programs running without it to tamper with it
[Helper]::runInAppcontainer(
    [Win32]::CreateRestrictedToken([Win32]::OpenProcessToken([Win32]::GetCurrentProcess(),8 -bor 2 -bor 128 <# flags TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT #>),1 <# flag DISABLE_MAX_PRIVILEGE #>,0,0,0,0,0,0),
    [Win32]::CreateAppContainerProfile("Meterel.MidBox.AppContainer","Meterel.MidBox.AppContainer","Meterel.MidBox.AppContainer",0,0),
    (Get-Content -ErrorAction SilentlyContinue "$([Environment]::GetFolderPath("ProgramFiles"))\MidBox\data\sandboxes\$([Environment]::UserName)\capabilities.txt" | Where-Object {$_ -match "^\s*(\w+)"} | ForEach-Object {[Win32]::DeriveCapabilitySidsFromName($Matches[1])}),
    $cmd
)

#[Win32]::DeleteAppContainerProfile("Meterel.MidBox.AppContainer") appcontainer is required to be present for some programs like notepad, it's later deleted in init_sandbox.ps1