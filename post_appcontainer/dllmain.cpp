// Made by Meterel
// https://meterel.com

#include "pch.h"
#include "detours\include\detours.h"
#include <ShlObj.h>
#include <strsafe.h>
#include <SubAuth.h>
#include <aclapi.h>

/*
	other hooking methods have been tried but had drawbacks that led me to using a library
	trampolines: must hardcode op boundaries making it function dependant and architecture dependant, can't relocate disrupted ops that are relative
	iat hooking: hooks only in a singular module
	eat hooking: requires free pages near the dll in witch the function to hook is to relocate exports (architecture independent) or allocate a trampoline
	sometimes free pages near the dll wouldn't be available, meaning that the 32 bit pointer in the export table or in the header couldn't reach

	some proc addresses are gotten trough another dll rather than what the docs say because the dll in the docs redirects to the other

	A funcs usually call W funcs internally
*/

#define error(x){ \
	char errorStr[256]; /*must be here for thread safety*/ \
	StringCbPrintfA(errorStr,sizeof(errorStr),"Error %u in %s at %s",GetLastError(),__func__,#x); \
	MessageBoxA(NULL,errorStr,"MidBox DLL error",MB_ICONERROR); \
}
#define check(x)      \
	if(!(x)){         \
		error(x);     \
		return FALSE; \
	}

HANDLE apiBroker;
WCHAR root[256];

enum struct RemoteFunc :unsigned char {
	SetCursorPos,
	SetPhysicalCursorPos,
	ClipCursor,
	ChangeDisplaySettingsExW,
	ChangeDisplaySettingsExA
};


HRESULT(WINAPI* SHGetKnownFolderPath_original)(REFKNOWNFOLDERID, DWORD, HANDLE, PWSTR*);
HRESULT WINAPI SHGetKnownFolderPath_wrapper(REFKNOWNFOLDERID rfid, DWORD dwFlags, HANDLE hToken, PWSTR* ppszPath) {
	return SHGetKnownFolderPath_original(rfid, dwFlags | KF_FLAG_NO_PACKAGE_REDIRECTION, hToken, ppszPath);
}

//same signature of SHGetKnownFolderIDList
HRESULT(WINAPI* SHGetKnownFolderIDList_Internal_original)(REFKNOWNFOLDERID, DWORD, HANDLE, PIDLIST_ABSOLUTE*);
HRESULT WINAPI SHGetKnownFolderIDList_Internal_wrapper(REFKNOWNFOLDERID rfid, DWORD dwFlags, HANDLE hToken, PIDLIST_ABSOLUTE* ppidl) {
	return SHGetKnownFolderIDList_Internal_original(rfid, dwFlags | KF_FLAG_NO_PACKAGE_REDIRECTION, hToken, ppidl);
}

HRESULT(WINAPI* SHGetFolderPathW_original)(HWND, int, HANDLE, DWORD, LPWSTR);
HRESULT WINAPI SHGetFolderPathW_wrapper(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPWSTR pszPath) {
	if (csidl != CSIDL_LOCAL_APPDATA) return SHGetFolderPathW_original(hwnd, csidl, hToken, dwFlags, pszPath);

	PWSTR str;
	const auto r = SHGetKnownFolderPath(FOLDERID_LocalAppData, NULL, hToken, &str);
	if (r != S_OK) return r;
#pragma warning(push)
#pragma warning(disable : 4996)
	wcscpy(pszPath, str);
#pragma warning(pop)
	CoTaskMemFree(str);
	return r;
}

HRESULT(WINAPI* SHGetFolderPathEx_original)(REFKNOWNFOLDERID, DWORD, HANDLE, LPWSTR, UINT);
HRESULT WINAPI SHGetFolderPathEx_wrapper(REFKNOWNFOLDERID rfid, DWORD dwFlags, HANDLE hToken, LPWSTR pszPath, UINT cchPath) {
	return SHGetFolderPathEx_original(rfid, dwFlags | KF_FLAG_NO_PACKAGE_REDIRECTION, hToken, pszPath, cchPath);
}


//named pipes must start with \\.\pipe\LOCAL\ inside appcontainers according to https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea or else pipe funcs will return errors
//the functions below modify internal ones that are used to parse paths to make pipe paths local
PCWSTR globalToLocalPipe(PCWSTR path) {
	const WCHAR pipe[] = L"\\\\.\\pipe\\";
	const auto pipe_len = ARRAYSIZE(pipe) - 1;
	const WCHAR local[] = L"LOCAL\\";
	const auto local_len = ARRAYSIZE(local) - 1;

	//check for NULL because hooked funcs may return an error gracefully
	if (!path || wcsncmp(path, pipe, pipe_len) || !wcsncmp(path + pipe_len, local, local_len)) return path;

	const auto newPath = new WCHAR[wcslen(path) + local_len + 1];
#pragma warning(push)
#pragma warning(disable : 4996)
	wcscpy(newPath, pipe);
	wcscat(newPath, local);
	wcscat(newPath, path + pipe_len);
#pragma warning(pop)

	return newPath;
}

BOOLEAN(WINAPI* RtlDosPathNameToNtPathName_U_original)(PCWSTR, PUNICODE_STRING, PWSTR*, void*);
BOOLEAN WINAPI RtlDosPathNameToNtPathName_U_wrapper(PCWSTR DosFileName, PUNICODE_STRING NtFileName, PWSTR* FilePart, void* RelativeName) {
	const auto newPath = globalToLocalPipe(DosFileName);
	const auto r = RtlDosPathNameToNtPathName_U_original(newPath, NtFileName, FilePart, RelativeName);
	if (newPath != DosFileName) delete[] newPath;
	return r;
}

NTSTATUS(WINAPI* RtlDosPathNameToNtPathName_U_WithStatus_original)(PCWSTR, PUNICODE_STRING, PWSTR*, void*);
NTSTATUS WINAPI RtlDosPathNameToNtPathName_U_WithStatus_wrapper(PCWSTR DosFileName, PUNICODE_STRING NtFileName, PWSTR* FilePart, void* RelativeName) {
	const auto newPath = globalToLocalPipe(DosFileName);
	const auto r = RtlDosPathNameToNtPathName_U_WithStatus_original(newPath, NtFileName, FilePart, RelativeName);
	if (newPath != DosFileName) delete[] newPath;
	return r;
}

BOOLEAN(WINAPI* RtlDosPathNameToRelativeNtPathName_U_original)(PCWSTR, PUNICODE_STRING, PWSTR*, void*);
BOOLEAN WINAPI RtlDosPathNameToRelativeNtPathName_U_wrapper(PCWSTR DosFileName, PUNICODE_STRING NtFileName, PWSTR* FilePart, void* RelativeName) {
	const auto newPath = globalToLocalPipe(DosFileName);
	const auto r = RtlDosPathNameToRelativeNtPathName_U_original(newPath, NtFileName, FilePart, RelativeName);
	if (newPath != DosFileName) delete[] newPath;
	return r;
}

NTSTATUS(WINAPI* RtlDosPathNameToRelativeNtPathName_U_WithStatus_original)(PCWSTR, PUNICODE_STRING, PWSTR*, void*);
NTSTATUS WINAPI RtlDosPathNameToRelativeNtPathName_U_WithStatus_wrapper(PCWSTR DosFileName, PUNICODE_STRING NtFileName, PWSTR* FilePart, void* RelativeName) {
	const auto newPath = globalToLocalPipe(DosFileName);
	const auto r = RtlDosPathNameToRelativeNtPathName_U_WithStatus_original(newPath, NtFileName, FilePart, RelativeName);
	if (newPath != DosFileName) delete[] newPath;
	return r;
}

//only named pipe func that doesn't convert the path internally
BOOL(WINAPI* WaitNamedPipeW_original)(LPCWSTR, DWORD);
BOOL WINAPI WaitNamedPipeW_wrapper(LPCWSTR lpNamedPipeName, DWORD nTimeOut) {
	const auto newPath = globalToLocalPipe(lpNamedPipeName);
	const auto r = WaitNamedPipeW_original(newPath, nTimeOut);
	if (newPath != lpNamedPipeName) delete[] newPath;
	return r;
}


struct SetCursorPosParams {
	RemoteFunc func;
	int x;
	int y;
};

BOOL(WINAPI* SetCursorPos_original)(int, int);
BOOL WINAPI SetCursorPos_wrapper(int X, int Y) {
	SetCursorPosParams param{ RemoteFunc::SetCursorPos,X,Y };

	unsigned char r;
	DWORD read;
	check(TransactNamedPipe(apiBroker, &param, sizeof(param), &r, sizeof(r), &read, NULL));

	return r;
}

BOOL(WINAPI* SetPhysicalCursorPos_original)(int, int);
BOOL WINAPI SetPhysicalCursorPos_wrapper(int X, int Y) {
	SetCursorPosParams param{ RemoteFunc::SetPhysicalCursorPos,X,Y };

	unsigned char r;
	DWORD read;
	check(TransactNamedPipe(apiBroker, &param, sizeof(param), &r, sizeof(r), &read, NULL));

	return r;
}

BOOL(WINAPI* ClipCursor_original)(CONST RECT*);
BOOL WINAPI ClipCursor_wrapper(CONST RECT* lpRect) {
	struct {
		RemoteFunc func = RemoteFunc::ClipCursor;
		bool isNull;
		RECT rect;
	} param;

	param.isNull = !lpRect;
	if (lpRect) param.rect = *lpRect;

	unsigned char r;
	DWORD read;
	check(TransactNamedPipe(apiBroker, &param, sizeof(param), &r, sizeof(r), &read, NULL));

	return r;
}

LONG(WINAPI* ChangeDisplaySettingsExW_original)(LPCWSTR, DEVMODEW*, HWND, DWORD, LPVOID);
LONG WINAPI ChangeDisplaySettingsExW_wrapper(LPCWSTR lpszDeviceName, DEVMODEW* lpDevMode, HWND hwnd, DWORD dwflags, LPVOID lParam) {
	struct {
		RemoteFunc func = RemoteFunc::ChangeDisplaySettingsExW;
		WCHAR lpszDeviceName[32]; //length is from DISPLAY_DEVICE.DeviceName
		bool isLpDevModeNull;
		DEVMODEW lpDevMode;
		DWORD dwflags;
	} param;

	if (lpszDeviceName) wcscpy_s(param.lpszDeviceName, lpszDeviceName);
	else *param.lpszDeviceName = 0;
	param.isLpDevModeNull = !lpDevMode;
	if (lpDevMode) param.lpDevMode = *lpDevMode;
	param.dwflags = dwflags;

	LONG r;
	DWORD read;
	check(TransactNamedPipe(apiBroker, &param, sizeof(param), &r, sizeof(r), &read, NULL));

	return r;
}

//doesn't call the W func internally
LONG(WINAPI* ChangeDisplaySettingsExA_original)(LPCSTR, DEVMODEA*, HWND, DWORD, LPVOID);
LONG WINAPI ChangeDisplaySettingsExA_wrapper(LPCSTR lpszDeviceName, DEVMODEA* lpDevMode, HWND hwnd, DWORD dwflags, LPVOID lParam) {
	struct {
		RemoteFunc func = RemoteFunc::ChangeDisplaySettingsExA;
		CHAR lpszDeviceName[32]; //length is from DISPLAY_DEVICE.DeviceName
		bool isLpDevModeNull;
		DEVMODEA lpDevMode;
		DWORD dwflags;
	} param;

	if (lpszDeviceName) strcpy_s(param.lpszDeviceName, lpszDeviceName);
	else *param.lpszDeviceName = 0;
	param.isLpDevModeNull = !lpDevMode;
	if (lpDevMode) param.lpDevMode = *lpDevMode;
	param.dwflags = dwflags;

	LONG r;
	DWORD read;
	check(TransactNamedPipe(apiBroker, &param, sizeof(param), &r, sizeof(r), &read, NULL));

	return r;
}


//signature from https://github.com/je5442804/CreateProcessInternalW-Full/blob/main/CreateProcessInternalW-Full/process.cpp
BOOL(WINAPI* CreateProcessInternalW_original)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, OPTIONAL PHANDLE);
BOOL WINAPI CreateProcessInternalW_wrapper(
	HANDLE hUserToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	OPTIONAL PHANDLE hRestrictedUserToken //NULL
) {
	const auto r = CreateProcessInternalW_original(hUserToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hRestrictedUserToken);
	if (!r) return r;

	USHORT procArch;
	USHORT osArch;
	WCHAR cmd[256];
	STARTUPINFO si{ sizeof(si) };
	PROCESS_INFORMATION pi;

	if (!IsWow64Process2(lpProcessInformation->hProcess, &procArch, &osArch)) {
		error(IsWow64Process2);
		goto end;
	}

	StringCbPrintf(cmd, sizeof(cmd), L"\"%sinjector%s.exe\" %u", root, procArch == IMAGE_FILE_MACHINE_UNKNOWN && osArch != IMAGE_FILE_MACHINE_I386 && osArch != IMAGE_FILE_MACHINE_ARM ? L"64" : L"32", lpProcessInformation->dwProcessId);
	if (!CreateProcessInternalW_original(NULL, NULL, cmd, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi, NULL)) {
		error(CreateProcessInternalW_original);
		goto end;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

end:
	if (!(dwCreationFlags & CREATE_SUSPENDED)) ResumeThread(lpProcessInformation->hThread);
	return r;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	if (ul_reason_for_call != DLL_PROCESS_ATTACH) return TRUE;


#define PIPE_NAME L"\\\\.\\pipe\\midbox_api_broker_for_"
	WCHAR pipeName[256] = PIPE_NAME;
	DWORD pipeNameFreeSize = ARRAYSIZE(pipeName) - (ARRAYSIZE(PIPE_NAME) - 1);
	check(GetUserName(pipeName + ARRAYSIZE(PIPE_NAME) - 1, &pipeNameFreeSize));

	for (;;) {
		apiBroker = CreateFile(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (apiBroker != INVALID_HANDLE_VALUE) break;
		check(GetLastError() == ERROR_PIPE_BUSY);
		check(WaitNamedPipe(pipeName, 5000));
	}

	PSECURITY_DESCRIPTOR pipeDescriptorBuffer;
	PSID pipeOwner;
	check(GetSecurityInfo(apiBroker, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &pipeOwner, NULL, NULL, NULL, &pipeDescriptorBuffer) == ERROR_SUCCESS); //the returned descriptor is invalid and is only used as a buffer

	DWORD tokenInfoSize;
	GetTokenInformation(GetCurrentProcessToken(), TokenUser, NULL, 0, &tokenInfoSize);
	const auto tokenInfo = new char[tokenInfoSize];
	check(GetTokenInformation(GetCurrentProcessToken(), TokenUser, tokenInfo, tokenInfoSize, &tokenInfoSize));

	check(EqualSid(pipeOwner, ((TOKEN_USER*)tokenInfo)->User.Sid)); //must check, or may leak sensitive data to an impersonator because the buffers aren't zeroed
	LocalFree(pipeDescriptorBuffer);
	delete[] tokenInfo;

	DWORD pipeMode = PIPE_READMODE_MESSAGE;
	check(SetNamedPipeHandleState(apiBroker, &pipeMode, NULL, NULL));


	check(GetModuleFileName(hModule, root, ARRAYSIZE(root)));
	*(wcsrchr(root, '\\') + 1) = 0;



	const auto windowsStorage = LoadLibrary(L"windows.storage.dll");
	check(windowsStorage);

	const auto kernelbase = LoadLibrary(L"KernelBase.dll");
	check(kernelbase);

	const auto ntdll = LoadLibrary(L"ntdll.dll");
	check(ntdll);

	const auto user32 = LoadLibrary(L"User32.dll");
	check(user32);


	check(SHGetKnownFolderPath_original = (HRESULT(WINAPI*)(REFKNOWNFOLDERID, DWORD, HANDLE, PWSTR*))GetProcAddress(windowsStorage, "SHGetKnownFolderPath"));
	check(SHGetKnownFolderIDList_Internal_original = (HRESULT(WINAPI*)(REFKNOWNFOLDERID, DWORD, HANDLE, PIDLIST_ABSOLUTE*))GetProcAddress(windowsStorage, "SHGetKnownFolderIDList_Internal"));
	check(SHGetFolderPathW_original = (HRESULT(WINAPI*)(HWND, int, HANDLE, DWORD, LPWSTR))GetProcAddress(windowsStorage, "SHGetFolderPathW"));
	check(SHGetFolderPathEx_original = (HRESULT(WINAPI*)(REFKNOWNFOLDERID, DWORD, HANDLE, LPWSTR, UINT))GetProcAddress(windowsStorage, "SHGetFolderPathEx"));

	check(RtlDosPathNameToNtPathName_U_original = (BOOLEAN(WINAPI*)(PCWSTR, PUNICODE_STRING, PWSTR*, void*))GetProcAddress(ntdll, "RtlDosPathNameToNtPathName_U"));
	check(RtlDosPathNameToNtPathName_U_WithStatus_original = (NTSTATUS(WINAPI*)(PCWSTR, PUNICODE_STRING, PWSTR*, void*))GetProcAddress(ntdll, "RtlDosPathNameToNtPathName_U_WithStatus"));
	check(RtlDosPathNameToRelativeNtPathName_U_original = (BOOLEAN(WINAPI*)(PCWSTR, PUNICODE_STRING, PWSTR*, void*))GetProcAddress(ntdll, "RtlDosPathNameToRelativeNtPathName_U"));
	check(RtlDosPathNameToRelativeNtPathName_U_WithStatus_original = (NTSTATUS(WINAPI*)(PCWSTR, PUNICODE_STRING, PWSTR*, void*))GetProcAddress(ntdll, "RtlDosPathNameToRelativeNtPathName_U_WithStatus"));
	check(WaitNamedPipeW_original = (BOOL(WINAPI*)(LPCWSTR, DWORD))GetProcAddress(kernelbase, "WaitNamedPipeW"));

	check(SetCursorPos_original = (BOOL(WINAPI*)(int, int))GetProcAddress(user32, "SetCursorPos"));
	check(SetPhysicalCursorPos_original = (BOOL(WINAPI*)(int, int))GetProcAddress(user32, "SetPhysicalCursorPos"));
	check(ClipCursor_original = (BOOL(WINAPI*)(CONST RECT*))GetProcAddress(user32, "ClipCursor"));
	check(ChangeDisplaySettingsExW_original = (LONG(WINAPI*)(LPCWSTR, DEVMODEW*, HWND, DWORD, LPVOID))GetProcAddress(user32, "ChangeDisplaySettingsExW"));
	check(ChangeDisplaySettingsExA_original = (LONG(WINAPI*)(LPCSTR, DEVMODEA*, HWND, DWORD, LPVOID))GetProcAddress(user32, "ChangeDisplaySettingsExA"));

	check(CreateProcessInternalW_original = (BOOL(WINAPI*)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, OPTIONAL PHANDLE))GetProcAddress(kernelbase, "CreateProcessInternalW"));


	DetourTransactionBegin();

	DetourAttach(&(void*&)SHGetKnownFolderPath_original, SHGetKnownFolderPath_wrapper);
	DetourAttach(&(void*&)SHGetKnownFolderIDList_Internal_original, SHGetKnownFolderIDList_Internal_wrapper);
	DetourAttach(&(void*&)SHGetFolderPathW_original, SHGetFolderPathW_wrapper);
	DetourAttach(&(void*&)SHGetFolderPathEx_original, SHGetFolderPathEx_wrapper);

	DetourAttach(&(void*&)RtlDosPathNameToNtPathName_U_original, RtlDosPathNameToNtPathName_U_wrapper);
	DetourAttach(&(void*&)RtlDosPathNameToNtPathName_U_WithStatus_original, RtlDosPathNameToNtPathName_U_WithStatus_wrapper);
	DetourAttach(&(void*&)RtlDosPathNameToRelativeNtPathName_U_original, RtlDosPathNameToRelativeNtPathName_U_wrapper);
	DetourAttach(&(void*&)RtlDosPathNameToRelativeNtPathName_U_WithStatus_original, RtlDosPathNameToRelativeNtPathName_U_WithStatus_wrapper);
	DetourAttach(&(void*&)WaitNamedPipeW_original, WaitNamedPipeW_wrapper);

	DetourAttach(&(void*&)SetCursorPos_original, SetCursorPos_wrapper);
	DetourAttach(&(void*&)SetPhysicalCursorPos_original, SetPhysicalCursorPos_wrapper);
	DetourAttach(&(void*&)ClipCursor_original, ClipCursor_wrapper);
	DetourAttach(&(void*&)ChangeDisplaySettingsExW_original, ChangeDisplaySettingsExW_wrapper);
	DetourAttach(&(void*&)ChangeDisplaySettingsExA_original, ChangeDisplaySettingsExA_wrapper);

	DetourAttach(&(void*&)CreateProcessInternalW_original, CreateProcessInternalW_wrapper);

	DetourTransactionCommit();


	return TRUE;
}