// Made by Meterel
// https://meterel.com

#pragma comment(lib,"Shlwapi.lib")

#include <Windows.h>
#include <strsafe.h>
#include <shlwapi.h>

char error[256];
#define check(x) \
	if(!(x)){ \
		StringCbPrintfA(error,sizeof(error),"Error %u on %s",GetLastError(),#x); \
		MessageBoxA(NULL,error,"MidBox DLL injector error",MB_ICONERROR); \
		return 0; \
	}

int APIENTRY WinMain(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nShowCmd
)
{
	WCHAR dll[256];
	check(GetModuleFileName(NULL, dll, ARRAYSIZE(dll)));
	*(wcsrchr(dll, '\\') + 1) = 0;
	wcscat_s(dll,
#ifdef _WIN64
		L"post_appcontainer64.dll"
#else
		L"post_appcontainer32.dll"
#endif
	);
	const auto dllSize = (wcslen(dll) + 1) * sizeof(*dll);

	const auto kernel32 = GetModuleHandle(L"kernel32.dll");
	check(kernel32);
	const auto LoadLibraryW_addr = GetProcAddress(kernel32, "LoadLibraryW");
	check(LoadLibraryW_addr);


	const auto handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, StrToIntA(lpCmdLine));
	check(handle);

	const auto remoteAddr = VirtualAllocEx(handle, NULL, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	check(remoteAddr);
	check(WriteProcessMemory(handle, remoteAddr, dll, dllSize, NULL));

	const auto thread = CreateRemoteThread(handle, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryW_addr, remoteAddr, NULL, NULL);
	check(thread);

	WaitForSingleObject(thread, INFINITE);
	check(VirtualFreeEx(handle, remoteAddr, 0, MEM_RELEASE));
	return 1;
}