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
#include <fstream>
#include <filesystem>
#include <vector>

#include "logger.hpp"
#include "raw_driver.hpp"
#include "file_utils.hpp"
#include "service_utils.hpp"

#define MHYPROT_SERVICE_NAME "mhyprot2"
#define MHYPROT_DISPLAY_NAME "mhyprot2"
#define MHYPROT_SYSFILE_NAME "mhyprot.sys"
#define MHYPROT_SYSMODULE_NAME "mhyprot2.sys"

#define MHYPROT_DEVICE_NAME "\\\\?\\\\mhyprot2"

#define MHYPROT_IOCTL_INITIALIZE                0x80034000
#define MHYPROT_IOCTL_READ_KERNEL_MEMORY        0x83064000
#define MHYPROT_IOCTL_READ_WRITE_USER_MEMORY    0x81074000
#define MHYPROT_IOCTL_ENUM_PROCESS_MODULES      0x82054000
#define MHYPROT_IOCTL_GET_SYSTEM_UPTIME         0x80134000
#define MHYPROT_IOCTL_ENUM_PROCESS_THREADS      0x83024000
#define MHYPROT_IOCTL_TERMINATE_PROCESS         0x81034000

#define MHYPROT_ACTION_READ  0x0
#define MHYPROT_ACTION_WRITE 0x1

#define MHYPROT_OFFSET_SEEDMAP 0xA0E8

#define MHYPROT_ENUM_PROCESS_MODULE_SIZE 0x3A0

#define MHYPROT_ENUM_PROCESS_THREADS_SIZE 0xA8
#define MHYPROT_ENUM_PROCESS_THREADS_CODE 0x88

#ifdef __cplusplus
extern "C" {
#endif

	uint64_t generate_key(uint64_t seed);

#ifdef __cplusplus
};
#endif

namespace mhyprot
{
	typedef struct _MHYPROT_INITIALIZE
	{
		uint32_t _m_001;
		uint32_t _m_002;
		uint64_t _m_003;
	} MHYPROT_INITIALIZE, *PMHYPROT_INITIALIZE;

	typedef struct _MHYPROT_KERNEL_READ_REQUEST
	{
		uint64_t	address;
		ULONG		size;
	} MHYPROT_KERNEL_READ_REQUEST, *PMHYPROT_KERNEL_READ_REQUEST;

	typedef struct _MHYPROT_USER_READ_WRITE_REQUEST
	{
		uint64_t	response;
		uint32_t	action_code;
		uint32_t	reserved_01;
		uint32_t	process_id;
		uint32_t	reserved_02;
		uint64_t	buffer;
		uint64_t	address;
		ULONG		size;
		ULONG		reverved_03;
	} MHYPROT_USER_READ_WRITE_REQUEST, *PMHYPROT_USER_READ_WRITE_REQUEST;

	typedef struct _MHYPROT_ENUM_PROCESS_MODULES_REQUEST
	{
		uint32_t process_id;
		uint32_t max_count;
	} MHYPROT_ENUM_PROCESS_MODULES_REQUEST, * PMHYPROT_ENUM_PROCESS_MODULES_REQUEST;

	typedef struct _MHYPROT_ENUM_PROCESS_THREADS_REQUEST
	{
		uint32_t validation_code;
		uint32_t process_id;
		uint32_t owner_process_id;
	} MHYPROT_ENUM_PROCESS_THREADS_REQUEST, * PMHYPROT_ENUM_PROCESS_THREADS_REQUEST;

	typedef struct _MHYPROT_THREAD_INFORMATION
	{
		uint64_t kernel_address;
		uint64_t start_address;
		bool unknown;
	} MHYPROT_THREAD_INFORMATION, * PMHYPROT_THREAD_INFORMATION;

	typedef struct _MHYPROT_TERMINATE_PROCESS_REQUEST
	{
		uint64_t response;
		uint32_t process_id;
	} MHYPROT_TERMINATE_PROCESS_REQUEST, * PMHYPROT_TERMINATE_PROCESS_REQUEST;

	namespace detail
	{
		inline HANDLE device_handle;
		inline uint64_t seedmap[312];
		inline SC_HANDLE mhyplot_service_handle;
	}

	bool init();
	void unload();

	namespace driver_impl
	{
		bool request_ioctl(const uint32_t ioctl_code, void* in_buffer, const size_t in_buffer_size);
		bool driver_init(bool debug_prints = false, bool print_seeds = false);
		void encrypt_payload(void* payload, const size_t size);

		bool read_kernel_memory(const uint64_t address, void* buffer, const size_t size);
		template<class T> __forceinline T read_kernel_memory(const uint64_t address)
		{
			T buffer;
			read_kernel_memory(address, &buffer, sizeof(T));
			return buffer;
		}

		bool read_process_memory(
			const uint32_t process_id,
			const uint64_t address, void* buffer, const size_t size
		);

		template<class T> __forceinline T read_process_memory(
			const uint32_t process_id, const uint64_t address
		)
		{
			T buffer;
			read_process_memory(process_id, address, &buffer, sizeof(T));
			return buffer;
		}

		bool write_process_memory(
			const uint32_t process_id,
			const uint64_t address, void* buffer, const size_t size
		);

		template<class T> __forceinline bool write_process_memory(
			const uint32_t process_id,
			const uint64_t address, const T value
		)
		{
			return write_process_memory(process_id, address, &value, sizeof(T));
		}

		bool get_process_modules(
			const uint32_t process_id, const uint32_t max_count,
			std::vector< std::pair<std::wstring, std::wstring> >& result
		);

		uint32_t get_system_uptime();

		bool get_process_threads(
			const uint32_t& process_id, const uint32_t& owner_process_id,
			std::vector<MHYPROT_THREAD_INFORMATION>& result
		);

		bool terminate_process(const uint32_t process_id);
	}
}
