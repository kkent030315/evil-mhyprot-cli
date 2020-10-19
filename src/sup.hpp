/*
 * MIT License
 *
 * Copyright (c) 2020 Kento Oki
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

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
	void perform_tests(const uint32_t process_id)
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

		logger::log("\n[>] snatching 5 modules loaded in the process using vulnerable driver...\n");

		std::vector<std::pair<std::wstring, std::wstring>> module_list;
		if (mhyprot::driver_impl::get_process_modules(process_id, 5, module_list))
		{
			for (auto& _module : module_list)
			{
				logger::log("[+] ---> %20ws : %ws\n", _module.first.c_str(), _module.second.c_str());
			}
			logger::log("[<] snatched!\n\n");
		}
		else
		{
			logger::log("[!] enum modules test failure\n");
		}

		logger::log("[<] performed\n");
	}
}