#pragma hdrstop
#include <windows.h>
#include <vcl.h>
#include <mmsystem.h>
#include <tlhelp32.h>
#define JMP(from, to) (int)(((int)to - (int)from) - 5);

bool EnablePrivilege()
{
	HANDLE hToken=NULL;
	if (OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken)) return true;
	LPCTSTR szPrivName = SE_DEBUG_NAME;
	BOOL fEnable = true;
	TOKEN_PRIVILEGES   tp;
	tp.PrivilegeCount = 1;
	LookupPrivilegeValue(NULL,szPrivName,&tp.Privileges[0].Luid);
	tp.Privileges[0].Attributes   =   fEnable   ?   SE_PRIVILEGE_ENABLED:0;
	AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL);
	return((GetLastError()   ==   ERROR_SUCCESS));
}



bool RemoteInject(String DLLPath,DWORD process_id)
{
	EnablePrivilege();
	void* ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS,false,process_id);
	if(!ProcessHandle) return false;
	char *lpszDll=AnsiString(DLLPath).c_str() ;
	DWORD dwSize, dwWritten;
	dwSize = lstrlenA( lpszDll ) + 1;
	LPVOID lpBuf = VirtualAllocEx( ProcessHandle, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE );
	if (!lpBuf) return false;
	WriteProcessMemory( ProcessHandle, lpBuf, (LPVOID)lpszDll, dwSize, &dwWritten );

	PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");
	HANDLE hThread=CreateRemoteThread( ProcessHandle, NULL, 0, pfnStartAddr, lpBuf, 0, NULL);
	if(!hThread) return false;

	WaitForSingleObject( hThread, INFINITE );
	VirtualFreeEx( ProcessHandle, lpBuf, dwSize, MEM_DECOMMIT );
	CloseHandle( hThread );
	return true;
}
