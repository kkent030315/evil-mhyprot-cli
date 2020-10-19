#include "win_utils.hpp"

//
// find the process id by specific name using ToolHelp32Snapshot
//
uint32_t win_utils::find_process_id(const std::string_view process_name)
{
	PROCESSENTRY32 processentry = {};

	const unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), &CloseHandle);

	if (!CHECK_HANDLE(snapshot.get()))
	{
		logger::log("[!] Failed to create ToolHelp32Snapshot [0x%lX]\n", GetLastError());
		return 0;
	}

	processentry.dwSize = sizeof(MODULEENTRY32);

	while (Process32Next(snapshot.get(), &processentry) == TRUE)
	{
		if (process_name.compare(processentry.szExeFile) == 0)
		{
			return processentry.th32ProcessID;
		}
	}

	return 0;
}

//
// find the base address of process by the pid using ToolHelp32Snapshot
//
uint64_t win_utils::find_base_address(const uint32_t process_id)
{
	MODULEENTRY32 module_entry = {};

	const unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id), &CloseHandle);

	if (!CHECK_HANDLE(snapshot.get()))
	{
		printf("[!] Failed to create ToolHelp32Snapshot [0x%lX]\n", GetLastError());
		return 0;
	}

	module_entry.dwSize = sizeof(module_entry);

	Module32First(snapshot.get(), &module_entry);

	return (uint64_t)module_entry.modBaseAddr;
}

//
// lookup base address of specific module that loaded in the system
// by NtQuerySystemInformation api
//
uint64_t win_utils::find_sysmodule_address_by_name(
	const std::string_view target_module_name,
	bool debug_prints
)
{
	const HMODULE module_handle = GetModuleHandle(TEXT("ntdll.dll"));

	if (!CHECK_HANDLE(module_handle))
	{
		logger::log("[!] failed to obtain ntdll.dll handle. (0x%lX)\n", module_handle);
		return 0;
	}

	pNtQuerySystemInformation NtQuerySystemInformation =
		(pNtQuerySystemInformation)GetProcAddress(module_handle, "NtQuerySystemInformation");

	if (!NtQuerySystemInformation)
	{
		logger::log("[!] failed to locate NtQuerySystemInformation. (0x%lX)\n", GetLastError());
		return 0;
	}

	NTSTATUS status;
	PVOID buffer;
	ULONG alloc_size = 0x10000;
	ULONG needed_size;

	do
	{
		buffer = calloc(1, alloc_size);

		if (!buffer)
		{
			logger::log("[!] failed to allocate buffer for query (0). (0x%lX)\n", GetLastError());
			return 0;
		}

		status = NtQuerySystemInformation(
			SystemModuleInformation,
			buffer,
			alloc_size,
			&needed_size
		);

		if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH)
		{
			logger::log("[!] failed to query system module information. NTSTATUS: 0x%llX\n", status);
			free(buffer);
			return 0;
		}

		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			free(buffer);
			buffer = NULL;
			alloc_size *= 2;
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (!buffer)
	{
		logger::log("[!] failed to allocate buffer for query (1). (0x%lX)\n", GetLastError());
		return 0;
	}

	PSYSTEM_MODULE_INFORMATION module_information = (PSYSTEM_MODULE_INFORMATION)buffer;

	logger::log("[>] looking for %s in sysmodules...\n", target_module_name.data());
	
	for (ULONG i = 0; i < module_information->Count; i++)
	{
		SYSTEM_MODULE_INFORMATION_ENTRY module_entry = module_information->Module[i];
		ULONG_PTR module_address = (ULONG_PTR)module_entry.DllBase;

		if (module_address < MIN_ADDRESS)
		{
			continue;
		}

		PCHAR module_name = module_entry.ImageName + module_entry.ModuleNameOffset;

		if (debug_prints)
		{
			logger::log("[+] sysmodule: %025s @ 0x%llX\n", module_name, module_address);
		}

		if (target_module_name.compare(module_name) == 0 ||
			std::string(module_name).find("mhyprot") != std::string::npos)
		{
			logger::log("[<] found\n");
			return module_address;
		}
	}

	free(buffer);
	return 0;
}
