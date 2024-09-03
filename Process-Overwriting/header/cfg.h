#pragma once

#ifndef CFG_H
#define CFG_H

#include <Windows.h>
#pragma comment(lib, "WindowsApp")

typedef BOOL(WINAPI* _SetProcessValidCallTargets)(
    HANDLE                  hProcess,
    PVOID                   VirtualAddress,
    SIZE_T                  RegionSize,
    ULONG                   NumberOfOffsets,
    PCFG_CALL_TARGET_INFO   OffsetInformation
);

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef LONG(NTAPI* MyNtQueryVirtualMemory)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);

int GetFunctionAddressFromDll(PSTR pszDllName,PSTR pszFunctionName,PVOID* ppvFunctionAddress);

BOOL DisableCfg(PROCESS_INFORMATION pProcessInfo, DWORD victim_size, PVOID victim_base_addr, DWORD cfg_size, PVOID cfg_base);

BOOL markCFGValid_std(PROCESS_INFORMATION pProcessInfo, PVOID pAddress);

#endif