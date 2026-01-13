param(
    $cmd
)
$ErrorActionPreference="stop"
trap{
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show($_,$MyInvocation.MyCommand,"OK","Error") | Out-Null
}

#according to https://learn.microsoft.com/en-us/dotnet/standard/native-interop/type-marshalling win32's BOOL (4 bytes) can be marshalled into a bool (1 byte)
#must ignore warnings or issues wrongful struct field never accessed warning from struct filled by marshaling
Add-Type -IgnoreWarnings @"
    using System;
    using System.IO;
    using System.IO.Pipes;
    using System.Threading;
    using System.Reflection;
    using System.Diagnostics;
    using System.Security.Principal;
    using System.Security.AccessControl;
    using System.Runtime.InteropServices;

    public class Win32{
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


        [DllImport("Userenv.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="DeleteAppContainerProfile")]
        static extern int _DeleteAppContainerProfile(string pszAppContainerName);
        public static void DeleteAppContainerProfile(string pszAppContainerName){
            if(_DeleteAppContainerProfile(pszAppContainerName)!=0) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());
        }

        [DllImport("Userenv.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="CreateAppContainerProfile")]
        static extern int _CreateAppContainerProfile(string pszAppContainerName,string pszDisplayName,string pszDescription,IntPtr pCapabilities,uint dwCapabilityCount,out IntPtr ppSidAppContainerSid);
        public static IntPtr CreateAppContainerProfile(string pszAppContainerName,string pszDisplayName,string pszDescription,IntPtr pCapabilities,uint dwCapabilityCount){
            IntPtr x;
            if(_CreateAppContainerProfile(pszAppContainerName,pszDisplayName,pszDescription,pCapabilities,dwCapabilityCount,out x)!=0) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());
            return x;
        }


        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("Advapi32.dll",SetLastError=true,EntryPoint="OpenProcessToken")]
        static extern bool _OpenProcessToken(IntPtr ProcessHandle,uint DesiredAccess,out IntPtr TokenHandle);
        public static IntPtr OpenProcessToken(IntPtr ProcessHandle,uint DesiredAccess){
            IntPtr x;
            if(!_OpenProcessToken(ProcessHandle,DesiredAccess,out x)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());
            return x;
        }

        [DllImport("Advapi32.dll",SetLastError=true,EntryPoint="CreateRestrictedToken")]
        static extern bool _CreateRestrictedToken(IntPtr ExistingTokenHandle,uint Flags,uint DisableSidCount,IntPtr SidsToDisable,uint DeletePrivilegeCount,IntPtr PrivilegesToDelete,uint RestrictedSidCount,IntPtr SidsToRestrict,out IntPtr NewTokenHandle);
        public static IntPtr CreateRestrictedToken(IntPtr ExistingTokenHandle,uint Flags,uint DisableSidCount,IntPtr SidsToDisable,uint DeletePrivilegeCount,IntPtr PrivilegesToDelete,uint RestrictedSidCount,IntPtr SidsToRestrict){
            IntPtr x;
            if(!_CreateRestrictedToken(ExistingTokenHandle,Flags,DisableSidCount,SidsToDisable,DeletePrivilegeCount,PrivilegesToDelete,RestrictedSidCount,SidsToRestrict,out x)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());
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
            if(!_GetTokenInformation(TokenHandle,TokenInformationClass,TokenInformation,TokenInformationLength,out x)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());
        }

        [DllImport("Advapi32.dll",SetLastError=true,EntryPoint="SetTokenInformation")]
        static extern bool _SetTokenInformation(IntPtr TokenHandle,int TokenInformationClass,IntPtr TokenInformation,uint TokenInformationLength);
        public static void SetTokenInformation(IntPtr TokenHandle,int TokenInformationClass,IntPtr TokenInformation,uint TokenInformationLength){
            if(!_SetTokenInformation(TokenHandle,TokenInformationClass,TokenInformation,TokenInformationLength)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());
        }


        [DllImport("Kernel32.dll",SetLastError=true,EntryPoint="LocalFree")]
        static extern IntPtr _LocalFree(IntPtr hMem);
        public static void LocalFree(IntPtr hMem){
            if(_LocalFree(hMem)!=(IntPtr)0) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());
        }

        [DllImport("kernelbase.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="DeriveCapabilitySidsFromName")]
        static extern bool _DeriveCapabilitySidsFromName(string CapName,out IntPtr CapabilityGroupSids,out uint CapabilityGroupSidCount,out IntPtr CapabilitySids,out uint CapabilitySidCount);
        public static SID_AND_ATTRIBUTES DeriveCapabilitySidsFromName(string CapName){
            IntPtr groupSids;
            uint groupSidsCount;
            IntPtr sids;
            uint sidsCount;
            if(!_DeriveCapabilitySidsFromName(CapName,out groupSids,out groupSidsCount,out sids,out sidsCount)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());

            for(int i=0;i<groupSidsCount;i++) LocalFree(Marshal.ReadIntPtr(groupSids+i*IntPtr.Size));
            LocalFree(groupSids);

            try{
                if(sidsCount!=1){
                    for(int i=0;i<sidsCount;i++) LocalFree(Marshal.ReadIntPtr(sids+i*IntPtr.Size));
                    throw new Exception("Unexpected number of SIDs of "+sidsCount+" at "+MethodBase.GetCurrentMethod().Name);
                }

                return new SID_AND_ATTRIBUTES{Sid=Marshal.ReadIntPtr(sids),Attributes=4 /* flag SE_GROUP_ENABLED */};
            }finally{
                LocalFree(sids);
            }
        }

        [DllImport("Kernel32.dll",SetLastError=true,EntryPoint="InitializeProcThreadAttributeList")]
        static extern bool _InitializeProcThreadAttributeList(IntPtr lpAttributeList,uint dwAttributeCount,uint dwFlags,ref UIntPtr lpSize);
        public static UIntPtr InitializeProcThreadAttributeListSize(uint dwAttributeCount){
            var x=(UIntPtr)0;
            _InitializeProcThreadAttributeList((IntPtr)0,dwAttributeCount,0,ref x);
            return x;
        }

        public static void InitializeProcThreadAttributeList(IntPtr lpAttributeList,uint dwAttributeCount,uint dwFlags,UIntPtr lpSize){
            if(!_InitializeProcThreadAttributeList(lpAttributeList,dwAttributeCount,dwFlags,ref lpSize)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());
        }

        [DllImport("Kernel32.dll",SetLastError=true,EntryPoint="UpdateProcThreadAttribute")]
        static extern bool _UpdateProcThreadAttribute(IntPtr lpAttributeList,uint dwFlags,UIntPtr Attribute,ref SECURITY_CAPABILITIES lpValue,UIntPtr cbSize,IntPtr lpPreviousValue,IntPtr lpReturnSize);
        public static void UpdateProcThreadAttribute(IntPtr lpAttributeList,uint dwFlags,UIntPtr Attribute,ref SECURITY_CAPABILITIES lpValue,UIntPtr cbSize,IntPtr lpPreviousValue,IntPtr lpReturnSize){
            if(!_UpdateProcThreadAttribute(lpAttributeList,dwFlags,Attribute,ref lpValue,cbSize,lpPreviousValue,lpReturnSize)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());
        }

        [DllImport("Advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="CreateProcessAsUserW")]
        static extern bool _CreateProcessAsUserW(IntPtr hToken,IntPtr lpApplicationName,string lpCommandLine,IntPtr lpProcessAttributes,IntPtr lpThreadAttributes,int bInheritHandles,uint dwCreationFlags,IntPtr lpEnvironment,IntPtr lpCurrentDirectory,ref STARTUPINFOEX lpStartupInfo,out PROCESS_INFORMATION lpProcessInformation);
        public static PROCESS_INFORMATION CreateProcessAsUser(IntPtr hToken,IntPtr lpApplicationName,string lpCommandLine,IntPtr lpProcessAttributes,IntPtr lpThreadAttributes,int bInheritHandles,uint dwCreationFlags,IntPtr lpEnvironment,IntPtr lpCurrentDirectory,ref STARTUPINFOEX lpStartupInfo){
            PROCESS_INFORMATION x;
            if(!_CreateProcessAsUserW(hToken,lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,lpEnvironment,lpCurrentDirectory,ref lpStartupInfo,out x)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());
            return x;
        }

        [DllImport("Kernel32.dll",SetLastError=true,EntryPoint="IsWow64Process2")]
        static extern bool _IsWow64Process2(IntPtr hProcess,out ushort pProcessMachine,out ushort pNativeMachine);
        public static Wow64Process2 IsWow64Process2(IntPtr hProcess){
            Wow64Process2 x;
            if(!_IsWow64Process2(hProcess,out x.ProcessMachine,out x.NativeMachine)) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());
            return x;
        }

        [DllImport("Kernel32.dll",SetLastError=true,EntryPoint="ResumeThread")]
        static extern uint _ResumeThread(IntPtr hThread);
        public static uint ResumeThread(IntPtr hThread){
            var x=_ResumeThread(hThread);
            if((int)x==-1) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());
            return x;
        }

        [DllImport("Advapi32.dll",SetLastError=true,EntryPoint="FreeSid")]
        static extern IntPtr _FreeSid(IntPtr pSid);
        public static void FreeSid(IntPtr pSid){
            if(_FreeSid(pSid)!=(IntPtr)0) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());
        }

        [DllImport("Kernel32.dll")]
        public static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);


        //broker apis
        public struct RECT{
            public int left;
            public int top;
            public int right;
            public int bottom;
        }

        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
        public struct DEVMODEW{
            [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)]
            public string dmDeviceName;
            public ushort dmSpecVersion;
            public ushort dmDriverVersion;
            public ushort dmSize;
            public ushort dmDriverExtra;
            public uint dmFields;
            public short dmOrientation;
            public short dmPaperSize;
            public short dmPaperLength;
            public short dmPaperWidth;
            public short dmScale;
            public short dmCopies;
            public short dmDefaultSource;
            public short dmPrintQuality;
            public short dmColor;
            public short dmDuplex;
            public short dmYResolution;
            public short dmTTOption;
            public short dmCollate;
            [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)]
            public string dmFormName;
            public ushort dmLogPixels;
            public uint dmBitsPerPel;
            public uint dmPelsWidth;
            public uint dmPelsHeight;
            public uint dmDisplayFlags;
            public uint dmDisplayFrequency;
            public uint dmICMMethod;
            public uint dmICMIntent;
            public uint dmMediaType;
            public uint dmDitherType;
            public uint dmReserved1;
            public uint dmReserved2;
            public uint dmPanningWidth;
            public uint dmPanningHeight;
        }

        public struct DEVMODEA{
            [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)]
            public string dmDeviceName;
            public ushort dmSpecVersion;
            public ushort dmDriverVersion;
            public ushort dmSize;
            public ushort dmDriverExtra;
            public uint dmFields;
            public short dmOrientation;
            public short dmPaperSize;
            public short dmPaperLength;
            public short dmPaperWidth;
            public short dmScale;
            public short dmCopies;
            public short dmDefaultSource;
            public short dmPrintQuality;
            public short dmColor;
            public short dmDuplex;
            public short dmYResolution;
            public short dmTTOption;
            public short dmCollate;
            [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)]
            public string dmFormName;
            public ushort dmLogPixels;
            public uint dmBitsPerPel;
            public uint dmPelsWidth;
            public uint dmPelsHeight;
            public uint dmDisplayFlags;
            public uint dmDisplayFrequency;
            public uint dmICMMethod;
            public uint dmICMIntent;
            public uint dmMediaType;
            public uint dmDitherType;
            public uint dmReserved1;
            public uint dmReserved2;
            public uint dmPanningWidth;
            public uint dmPanningHeight;
        }


        [DllImport("User32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="MessageBoxW")]
        static extern int _MessageBoxW(IntPtr hWnd,string lpText,string lpCaption,uint uType);
        public static int MessageBox(IntPtr hWnd,string lpText,string lpCaption,uint uType){
            var x=_MessageBoxW(hWnd,lpText,lpCaption,uType);
            if(x==0) throw new Exception(MethodBase.GetCurrentMethod().Name+" error "+Marshal.GetLastWin32Error());
            return x;
        }

        [DllImport("User32.dll")]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("Oleacc.dll")]
        public static extern IntPtr GetProcessHandleFromHwnd(IntPtr hwnd);

        [DllImport("Kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("User32.dll")]
        public static extern bool SetCursorPos(int X,int Y);

        [DllImport("User32.dll")]
        public static extern bool SetPhysicalCursorPos(int X,int Y);

        [DllImport("User32.dll")]
        public static extern bool ClipCursor(ref RECT lpRect);
        [DllImport("User32.dll")]
        public static extern bool ClipCursor(IntPtr lpRect);

        [DllImport("User32.dll")]
        public static extern int ChangeDisplaySettingsExW(IntPtr lpszDeviceName,ref DEVMODEW lpDevMode,IntPtr hwnd,uint dwflags,IntPtr lParam);
        [DllImport("User32.dll")]
        public static extern int ChangeDisplaySettingsExW(IntPtr lpszDeviceName,IntPtr lpDevMode,IntPtr hwnd,uint dwflags,IntPtr lParam);

        [DllImport("User32.dll")]
        public static extern int ChangeDisplaySettingsExA(IntPtr lpszDeviceName,ref DEVMODEA lpDevMode,IntPtr hwnd,uint dwflags,IntPtr lParam);
        [DllImport("User32.dll")]
        public static extern int ChangeDisplaySettingsExA(IntPtr lpszDeviceName,IntPtr lpDevMode,IntPtr hwnd,uint dwflags,IntPtr lParam);
    }

    class ApiBroker{
        //even if constants are bytes its still of type enum
        enum RemoteFunc:byte{
            SetCursorPos,
            SetPhysicalCursorPos,
            ClipCursor,
            ChangeDisplaySettingsExW,
            ChangeDisplaySettingsExA
        }

        struct Params{
            //param structs have func for memory alignment
            public struct SetCursorPos{
                public RemoteFunc func;
                public int x;
                public int y;
            }

            public struct ClipCursor{
                public RemoteFunc func;
                [MarshalAs(UnmanagedType.U1)] //marshaled bool size is 4 bytes
                public bool isNull;
                public Win32.RECT rect;
            }

            [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
            public struct ChangeDisplaySettingsExW{
                public RemoteFunc func;
                [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)]
                public string lpszDeviceName;
                [MarshalAs(UnmanagedType.U1)]
                public bool isLpDevModeNull;
                public Win32.DEVMODEW lpDevMode;
                public uint dwflags;
            }

            public struct ChangeDisplaySettingsExA{
                public RemoteFunc func;
                [MarshalAs(UnmanagedType.ByValArray,SizeConst=32)]
                public byte[] lpszDeviceName;
                [MarshalAs(UnmanagedType.U1)]
                public bool isLpDevModeNull;
                public Win32.DEVMODEA lpDevMode;
                public uint dwflags;
            }
        }


        public static string pipeName="midbox_api_broker_for_"+Environment.UserName;
        static int connections=0;
        static PipeSecurity acl=new PipeSecurity();
        static int bufferSize=0;
        static ApiBroker(){
            acl.SetAccessRule(new PipeAccessRule(Environment.UserName,PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,AccessControlType.Allow));
            acl.SetAccessRule(new PipeAccessRule(new SecurityIdentifier("S-1-15-2-1388956366-2258462785-1159399181-844480566-995560047-3502612569-1338837068"),PipeAccessRights.ReadWrite,AccessControlType.Allow));

            foreach(var x in typeof(Params).GetNestedTypes()) bufferSize=Math.Max(Marshal.SizeOf(x),bufferSize);
        }

        static void serverThread(object pipeObj){
            Interlocked.Increment(ref connections);

            var data=new byte[bufferSize];
            var dataHandle=GCHandle.Alloc(data,GCHandleType.Pinned);
            var dataAddr=dataHandle.AddrOfPinnedObject();
            try{
                using(var pipe=(NamedPipeServerStream)pipeObj) while(pipe.Read(data,0,data.Length)>0){
                    var windowAccess=false;
                    pipe.RunAsClient(()=>windowAccess=Win32.CloseHandle(Win32.GetProcessHandleFromHwnd(Win32.GetForegroundWindow())));
                    if(!windowAccess){
                        pipe.WriteByte(1); //lie
                        continue;
                    }

                    switch((RemoteFunc)data[0]){
                        case RemoteFunc.SetCursorPos:{
                            var param=Marshal.PtrToStructure<Params.SetCursorPos>(dataAddr);

                            pipe.WriteByte((byte)(Win32.SetCursorPos(param.x,param.y) ? 1 : 0));
                            break;
                        }case RemoteFunc.SetPhysicalCursorPos:{
                            var param=Marshal.PtrToStructure<Params.SetCursorPos>(dataAddr);

                            pipe.WriteByte((byte)(Win32.SetPhysicalCursorPos(param.x,param.y) ? 1 : 0));
                            break;
                        }case RemoteFunc.ClipCursor:{
                            var param=Marshal.PtrToStructure<Params.ClipCursor>(dataAddr);

                            pipe.WriteByte((byte)((param.isNull ? Win32.ClipCursor((IntPtr)0) : Win32.ClipCursor(ref param.rect)) ? 1 : 0));
                            break;
                        }case RemoteFunc.ChangeDisplaySettingsExW:{
                            var param=Marshal.PtrToStructure<Params.ChangeDisplaySettingsExW>(dataAddr);
                            var lpszDeviceName=param.lpszDeviceName=="" ? null : (GCHandle?)GCHandle.Alloc(param.lpszDeviceName,GCHandleType.Pinned);

                            try{
                                int r;
                                if(param.isLpDevModeNull) r=Win32.ChangeDisplaySettingsExW(lpszDeviceName.HasValue ? lpszDeviceName.Value.AddrOfPinnedObject() : (IntPtr)0,(IntPtr)0,(IntPtr)0,param.dwflags & 2 | 4 /* flags CDS_TEST | CDS_FULLSCREEN */,(IntPtr)0);
                                else{
                                    param.lpDevMode.dmSize=(ushort)Math.Min(Marshal.SizeOf(param.lpDevMode),param.lpDevMode.dmSize);
                                    param.lpDevMode.dmDriverExtra=0;
                                    r=Win32.ChangeDisplaySettingsExW(lpszDeviceName.HasValue ? lpszDeviceName.Value.AddrOfPinnedObject() : (IntPtr)0,ref param.lpDevMode,(IntPtr)0,param.dwflags & 2 | 4 /* flags CDS_TEST | CDS_FULLSCREEN */,(IntPtr)0);
                                }

                                pipe.Write(BitConverter.GetBytes(r),0,4);
                            }finally{
                                if(lpszDeviceName.HasValue) lpszDeviceName.Value.Free();
                            }
                            break;
                        }case RemoteFunc.ChangeDisplaySettingsExA:{
                            var param=Marshal.PtrToStructure<Params.ChangeDisplaySettingsExA>(dataAddr);
                            GCHandle? lpszDeviceName;
                            if(param.lpszDeviceName[0]==0) lpszDeviceName=null;
                            else{
                                param.lpszDeviceName[param.lpszDeviceName.Length-1]=0;
                                lpszDeviceName=GCHandle.Alloc(param.lpszDeviceName,GCHandleType.Pinned);
                            }

                            try{
                                int r;
                                if(param.isLpDevModeNull) r=Win32.ChangeDisplaySettingsExA(lpszDeviceName.HasValue ? lpszDeviceName.Value.AddrOfPinnedObject() : (IntPtr)0,(IntPtr)0,(IntPtr)0,param.dwflags & 2 | 4 /* flags CDS_TEST | CDS_FULLSCREEN */,(IntPtr)0);
                                else{
                                    param.lpDevMode.dmSize=(ushort)Math.Min(Marshal.SizeOf(param.lpDevMode),param.lpDevMode.dmSize);
                                    param.lpDevMode.dmDriverExtra=0;
                                    r=Win32.ChangeDisplaySettingsExA(lpszDeviceName.HasValue ? lpszDeviceName.Value.AddrOfPinnedObject() : (IntPtr)0,ref param.lpDevMode,(IntPtr)0,param.dwflags & 2 | 4 /* flags CDS_TEST | CDS_FULLSCREEN */,(IntPtr)0);
                                }

                                pipe.Write(BitConverter.GetBytes(r),0,4);
                            }finally{
                                if(lpszDeviceName.HasValue) lpszDeviceName.Value.Free();
                            }
                            break;
                        }
                    }
                }
            }catch(IOException){}
            catch(Exception e){
                Win32.MessageBox((IntPtr)0,e.ToString(),"MidBox API broker",16 /* flag MB_ICONERROR */);
            }
            dataHandle.Free();

            if(Interlocked.Decrement(ref connections)<=0) Environment.Exit(0);
        }

        public static void serveOnce(){
            var pipe=new NamedPipeServerStream(pipeName,PipeDirection.InOut,NamedPipeServerStream.MaxAllowedServerInstances,PipeTransmissionMode.Message,PipeOptions.None,0,0,acl);
            pipe.WaitForConnection();
            new Thread(serverThread).Start(pipe);
        }
    }


    public class Helper{
        //done in c# because in powershell CreateProcessAsUser returned an error
        public static void runInAppcontainer(IntPtr token,IntPtr appcontainerSid,Win32.SID_AND_ATTRIBUTES[] capabilities,string cmd){
            //removes the ace that grants access to the logon session, thus achieving sandbox to sandbox runtime isolation even tough they use the same appcontainer sid
            var tokenInfoSize=Win32.GetTokenInformationSize(token,6 /* flag TokenDefaultDacl */);
            var tokenInfo=Marshal.AllocHGlobal((int)tokenInfoSize);
            Win32.GetTokenInformation(token,6 /* flag TokenDefaultDacl */,tokenInfo,tokenInfoSize);

            var tokenAclPtr=Marshal.ReadIntPtr(tokenInfo);
            var tokenAclData=new byte[Marshal.PtrToStructure<Win32.ACL>(tokenAclPtr).AclSize];
            Marshal.Copy(tokenAclPtr,tokenAclData,0,tokenAclData.Length);
            var tokenAcl=new DiscretionaryAcl(false,false,new RawAcl(tokenAclData,0)); //IsContainer doesn't change its binary form
            Marshal.FreeHGlobal(tokenInfo);

            foreach(CommonAce i in tokenAcl)
                if(i.SecurityIdentifier.IsWellKnown(WellKnownSidType.LogonIdsSid)){
                    tokenAcl.Purge(i.SecurityIdentifier);
                    //tokenAcl.AddAccess((AccessControlType)i.AceType,new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null),i.AccessMask,i.InheritanceFlags,i.PropagationFlags); access can only be granted back to the initiator by knowing its explicit sid
                    break;
                }

            tokenAclData=new byte[IntPtr.Size+tokenAcl.BinaryLength];
            tokenAcl.GetBinaryForm(tokenAclData,IntPtr.Size);

            var tokenHandle=GCHandle.Alloc(tokenAclData,GCHandleType.Pinned);
            tokenInfo=tokenHandle.AddrOfPinnedObject();
            Marshal.WriteIntPtr(tokenInfo,tokenInfo+IntPtr.Size);

            Win32.SetTokenInformation(token,6 /* flag TokenDefaultDacl */,tokenInfo,(uint)tokenAclData.Length);
            tokenHandle.Free();


            var si=new Win32.STARTUPINFOEX();
            si.StartupInfo.cb=(uint)Marshal.SizeOf(si);

            var sc=new Win32.SECURITY_CAPABILITIES();
            sc.AppContainerSid=appcontainerSid;
            GCHandle? capabilitiesHandle;
            if(capabilities!=null){
                capabilitiesHandle=GCHandle.Alloc(capabilities,GCHandleType.Pinned);
                sc.Capabilities=capabilitiesHandle.Value.AddrOfPinnedObject();
                sc.CapabilityCount=(uint)capabilities.Length;
            }else capabilitiesHandle=null;

            var attributeListSize=Win32.InitializeProcThreadAttributeListSize(1);
            si.lpAttributeList=Marshal.AllocHGlobal((int)attributeListSize);
            Win32.InitializeProcThreadAttributeList(si.lpAttributeList,1,0,attributeListSize);
            Win32.UpdateProcThreadAttribute(si.lpAttributeList,0,(UIntPtr)131081 /* flag PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES */,ref sc,(UIntPtr)Marshal.SizeOf(sc),(IntPtr)0,(IntPtr)0);

            var pi=Win32.CreateProcessAsUser(token,(IntPtr)0,"\"$($PSScriptRoot.Replace("\","\\"))\\post_appcontainer.bat\" && "+cmd,(IntPtr)0,(IntPtr)0,0,16 | 524288 | 4 /* flags CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED */,(IntPtr)0,(IntPtr)0,ref si);
            var arch=Win32.IsWow64Process2(pi.hProcess);
            var injector=Process.Start("$($PSScriptRoot.Replace("\","\\"))\\dll\\injector"+(arch.ProcessMachine==0 /* flag IMAGE_FILE_MACHINE_UNKNOWN */ && arch.NativeMachine!=332 /* flag IMAGE_FILE_MACHINE_I386 */ && arch.NativeMachine!=448 /* flag IMAGE_FILE_MACHINE_ARM */ ? "64" : "32")+".exe",pi.dwProcessId.ToString());

            var brokerOffline=!File.Exists("\\\\.\\pipe\\"+ApiBroker.pipeName);
            if(brokerOffline) ApiBroker.serveOnce();

            injector.WaitForExit();
            Win32.ResumeThread(pi.hThread);

            Win32.CloseHandle(token);
            Win32.DeleteProcThreadAttributeList(si.lpAttributeList);
            Win32.FreeSid(appcontainerSid);
            if(capabilitiesHandle.HasValue){
                capabilitiesHandle.Value.Free();
                foreach(var x in capabilities) Win32.LocalFree(x.Sid);
            }
            Marshal.FreeHGlobal(si.lpAttributeList);
            Win32.CloseHandle(pi.hThread);
            Win32.CloseHandle(pi.hProcess);

            if(brokerOffline) for(;;) ApiBroker.serveOnce();
        }
    }
"@


[Win32]::DeleteAppContainerProfile("Meterel.MidBox.AppContainer") #appcontainer gets recreated every time to avoid programs running without it to tamper with it, fails randomly sometimes

$token=[Win32]::OpenProcessToken([Win32]::GetCurrentProcess(),8 -bor 2 -bor 128 <# flags TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT #>)
$restricted_token=[Win32]::CreateRestrictedToken($token,1 <# flag DISABLE_MAX_PRIVILEGE #>,0,0,0,0,0,0)
[Win32]::CloseHandle($token)

[Helper]::runInAppcontainer(
    $restricted_token,
    [Win32]::CreateAppContainerProfile("Meterel.MidBox.AppContainer","Meterel.MidBox.AppContainer","Meterel.MidBox.AppContainer",0,0),
    (Get-Content -ErrorAction SilentlyContinue "$([Environment]::GetFolderPath("ProgramFiles"))\MidBox\data\sandboxes\$([Environment]::UserName)\capabilities.txt" | Where-Object {$_ -match "^\s*(\w+)"} | ForEach-Object {[Win32]::DeriveCapabilitySidsFromName($Matches[1])}),
    $cmd
)

#[Win32]::DeleteAppContainerProfile("Meterel.MidBox.AppContainer") appcontainer is required to be present for some programs like notepad, it's later deleted in init_sandbox.ps1