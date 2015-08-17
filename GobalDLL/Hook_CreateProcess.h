
long CreateProcessW__ReturnAdr;
HANDLE WINAPI __declspec(naked) NormalCreateProcessW(  LPCWSTR lpApplicationName, LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation){
	asm{
		mov edi,edi
		push ebp
		mov ebp,esp
		jmp dword ptr [CreateProcessW__ReturnAdr]
	}
}

BOOL WINAPI NewCreateProcessW(
LPCWSTR lpApplicationName,
LPWSTR lpCommandLine,
LPSECURITY_ATTRIBUTES lpProcessAttributes,
LPSECURITY_ATTRIBUTES lpThreadAttributes,
BOOL bInheritHandles,
DWORD dwCreationFlags,
LPVOID lpEnvironment,
LPCWSTR lpCurrentDirectory,
LPSTARTUPINFOW lpStartupInfo,
LPPROCESS_INFORMATION lpProcessInformation)
{

bool GetRet = NormalCreateProcessW( lpApplicationName,
									lpCommandLine,
									lpProcessAttributes,
									lpThreadAttributes,
									bInheritHandles,
									dwCreationFlags,
									lpEnvironment,
									lpCurrentDirectory,
									lpStartupInfo,
									lpProcessInformation);

	InjectDll(MyPath,lpProcessInformation->hProcess);

return GetRet;
}

void LauchCreateProcessHook()
{
	   CreateProcessW__ReturnAdr = (long)GetProcAddress(GetModuleHandle("Kernel32"),AnsiString("CreateProcessW").c_str())+5  ;
	   AsmJump(CreateProcessW__ReturnAdr-5,NewCreateProcessW,0);
}