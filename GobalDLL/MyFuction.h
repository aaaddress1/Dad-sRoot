#pragma hdrstop
#include <windows.h>
#include <vcl.h>
#include <mmsystem.h>
#define JMP(from, to) (int)(((int)to - (int)from) - 5);

/********************************************************************************
	BASIC Function
	Without API To CheckOut Important Detail Of Memory.
********************************************************************************/
DWORD GetFuncAddr(HMODULE hModule, char* FuncName)
{
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = PIMAGE_EXPORT_DIRECTORY(pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress + (PBYTE)hModule);//俋滲

	PDWORD pAddressName = PDWORD((PBYTE)hModule + pExportDirectory->AddressOfNames); //滲靡想?蹈
	PWORD pAddressOfNameOrdinals = (PWORD)((PBYTE)hModule + pExportDirectory->AddressOfNameOrdinals); //滲杅靡備唗瘍桶硌渀
	PDWORD pAddresOfFunction = (PDWORD)((PBYTE)hModule + pExportDirectory->AddressOfFunctions); //滲杅華硊桶硌渀

	for (int index = 0; index < (pExportDirectory->NumberOfNames); index++)
	{
		char* pFunc = (char*)((long)hModule + *pAddressName);
		DWORD CurrentAddr = (DWORD)((PBYTE)hModule + pAddresOfFunction[*pAddressOfNameOrdinals]);

		if (!strcmp(pFunc, FuncName)) return (CurrentAddr);
		pAddressName++;
		pAddressOfNameOrdinals++;//ENT睿滲杅靡唗瘍杅郪謗跺甜俴杅郪肮奀賑雄硌渀(唗瘍杅郪笢腔唗瘍憩勤茼滲杅靡勤茼腔滲杅華硊腔杅郪坰竘)
	}
	return (NULL);
}
DWORD GetKernel32Mod()
{
	DWORD dRetn = 0;
	_asm{

		mov ebx, fs:[0x30] //PEB
			mov ebx, [ebx + 0x0c]//Ldr
			mov ebx, [ebx + 0x1c]//InInitializationOrderModuleList
		Search:
			   mov eax, [ebx + 0x08]//Point to Current Modual Base.
			   mov ecx, [ebx + 0x20]//Point to Current Name.
			   mov ecx, [ecx + 0x18]
			   cmp cl, 0x00//Test if Name[25] == \x00.
			   mov ebx, [ebx + 0x00]
			   jne Search
			   mov[dRetn], eax
	}
	return dRetn;
}
DWORD GetNTDllMod()
{
	DWORD dRetn = 0;
	_asm{
		mov ebx, fs:[0x30] //PEB
			mov ebx, [ebx + 0x0c]//Ldr
			mov ebx, [ebx + 0x1c]//InInitializationOrderModuleList
			mov eax, [ebx + 0x08]//Point to Current Modual Base.
			mov[dRetn], eax
	}
	return dRetn;
}
void SetMemExecuable(LPVOID Addr, DWORD Count)
{
	DWORD d;
	VirtualProtect(Addr, Count, PAGE_EXECUTE_READWRITE, &d);
}



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


bool InjectDll(String Path,void* hd)
{
	EnablePrivilege();
	if(NULL==hd) return false;
	char *lpszDll=AnsiString(Path).c_str() ;
	DWORD dwSize, dwWritten;
	dwSize = lstrlenA( lpszDll ) + 1;
	LPVOID lpBuf = VirtualAllocEx( hd, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE );
	if (!lpBuf){CloseHandle( hd );return false;}
	if ( WriteProcessMemory( hd, lpBuf, (LPVOID)lpszDll, dwSize, &dwWritten ) )
	{
		if ( dwWritten != dwSize )
		{
			VirtualFreeEx( hd, lpBuf, dwSize, MEM_DECOMMIT );
			CloseHandle( hd );
			return false;
		}
	}
	else{CloseHandle( hd );return false;}

	PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");
	HANDLE hThread=CreateRemoteThread( hd, NULL, 0, pfnStartAddr, lpBuf, 0, NULL);
	if(!hThread){CloseHandle( hd );return false;}
	WaitForSingleObject( hThread, INFINITE );
	VirtualFreeEx( hd, lpBuf, dwSize, MEM_DECOMMIT );
	CloseHandle( hThread );
	return true ;
}



String GetMyPath(HINSTANCE DllHinstDLL)
{
	String PathStr;
	try
	{
		wchar_t chModuleDir[260*2] ;
		GetModuleFileNameW(DllHinstDLL, chModuleDir, 260*2);
		PathStr = (chModuleDir);
		return PathStr;
	}
	catch(...) {}
	return ExtractFilePath(Application->ExeName);
}

void AsmJump(const DWORD lpAddress, LPCVOID Function, unsigned Nops){
	DWORD OldProtection;
	VirtualProtect((LPVOID)lpAddress,10,PAGE_EXECUTE_READWRITE, &OldProtection);
	*(LPBYTE)lpAddress = 0xE9;
	*(LPDWORD)(lpAddress + 1) = (DWORD)Function - (DWORD)lpAddress - 5;
	if ((bool)Nops)
		memset(((LPBYTE)lpAddress + 5), 0x90, Nops);
	VirtualProtect((LPVOID)lpAddress,10,OldProtection, &OldProtection);
}

void MEMwrite(PVOID address, void* val, int bytes){
	DWORD d, ds;
	VirtualProtect(address, bytes, PAGE_EXECUTE_READWRITE, &d);
	memcpy(address, val, bytes);
	VirtualProtect(address,bytes,d,&ds);
 }

