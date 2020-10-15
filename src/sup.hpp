#pragma once
#include <Windows.h>

#include "logger.hpp"
#include "win_utils.hpp"
#include "mhyprot.hpp"

namespace sup
{
	//
	// execute perform tests
	//
	__forceinline void perform_tests(const uint32_t process_id)
	{
		logger::log("\n[>] performing tests...\n");

		//
		// read dos-header using winapi
		//
		const uint64_t process_base_address = win_utils::find_base_address(process_id);

		logger::log("[+] module starts from: 0x%llX\n", process_base_address);
		logger::log("[>] reading dos/nt header using vulnerable driver...\n");

		//
		// read dos-header using vulnerable driver
		//
		IMAGE_DOS_HEADER dos_header = mhyprot::driver_impl::
			read_user_memory<IMAGE_DOS_HEADER>(process_id, process_base_address);

		//
		// read nt-header using vulnerable driver
		//
		IMAGE_NT_HEADERS nt_header = mhyprot::driver_impl::
			read_user_memory<IMAGE_NT_HEADERS>(process_id, process_base_address + dos_header.e_lfanew);

		//
		// image size of target process
		//
		DWORD image_size = nt_header.OptionalHeader.SizeOfImage;

		logger::log("[+] image size: 0x%lX\n", image_size);
		logger::log("[+] module ends at: 0x%llX\n", process_base_address + image_size);

		if (dos_header.e_magic == IMAGE_DOS_SIGNATURE)
		{
			logger::log("[+] dos header signature is correct!\n");
		}
		else
		{
			logger::log("[+] incorrect dos header received\n");
		}

		if (nt_header.Signature == IMAGE_NT_SIGNATURE)
		{
			logger::log("[+] nt header signature is correct!\n");
		}
		else
		{
			logger::log("[+] incorrect nt header received\n");
		}

		logger::log("[<] performed\n");
	}
}