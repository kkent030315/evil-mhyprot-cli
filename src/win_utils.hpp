#pragma once
#include <Windows.h>
#include <string>
#include <memory>
#include <TlHelp32.h>

#include "logger.hpp"
#include "nt.hpp"

#define CHECK_HANDLE(x) (x && x != INVALID_HANDLE_VALUE)
#define MIN_ADDRESS ((ULONG_PTR)0x8000000000000000)

namespace win_utils
{
	using unique_handle = std::unique_ptr<void, decltype(&CloseHandle)>;

	uint32_t find_process_id(const std::string_view process_name);
	uint64_t find_base_address(const uint32_t process_id);

	uint64_t obtain_sysmodule_address(const std::string_view target_module_name, bool debug_prints = false);
}