#pragma once

#include <iostream>
#include "ntddk.h"

#define _DEBUG

PVOID map_dll_image(const char* dll_name)
{
	HANDLE hFile = CreateFileA(dll_name,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "Couldn't open the file!" << std::hex << hFile << std::endl;
		return NULL;
	}
#ifdef _DEBUG
	std::cout << "File created, handle: " << std::hex << hFile << std::endl;
#endif
	HANDLE hSection = nullptr;
	NTSTATUS status = NtCreateSection(&hSection,
		SECTION_ALL_ACCESS,
		NULL,
		0,
		PAGE_READONLY,
		SEC_IMAGE,
		hFile
	);
	bool is_ok = false;
	if (status != STATUS_SUCCESS) {
		std::cerr << "NtCreateSection failed" << std::endl;
	}
	else {
#ifdef _DEBUG
		std::cerr << "NtCreateSection created at:" << std::hex << hSection << std::endl;
#endif
		is_ok = true;
	}

	CloseHandle(hFile);
	if (!is_ok) {
		return NULL;
	}

	DWORD protect = PAGE_EXECUTE_READWRITE;
	PVOID sectionBaseAddress = NULL;
	SIZE_T viewSize = 0;
	SECTION_INHERIT inheritDisposition = ViewShare; //VIEW_SHARE
	if ((status = NtMapViewOfSection(hSection,
		NtCurrentProcess(),
		&sectionBaseAddress,
		NULL,
		NULL,
		NULL,
		&viewSize,
		inheritDisposition,
		NULL,
		protect)
		) != STATUS_SUCCESS)
	{
		is_ok = false;
		std::wcout << "[ERROR] NtMapViewOfSection failed, status : " << std::hex << status << "\n";
	}
	else {
#ifdef _DEBUG
		std::wcout << "Section BaseAddress: " << std::hex << sectionBaseAddress << "\n";
#endif
		is_ok = true;
	}
	if (!is_ok) {
		return NULL;
	}
	return sectionBaseAddress;
}
