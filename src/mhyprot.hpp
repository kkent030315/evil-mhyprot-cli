#pragma once
#include <Windows.h>
#include <fstream>
#include <filesystem>

#include "logger.hpp"
#include "raw_driver.hpp"
#include "file_utils.hpp"
#include "service_utils.hpp"

#define MHYPROT_SERVICE_NAME "mhyprot2"
#define MHYPROT_DISPLAY_NAME "mhyprot2"
#define MHYPROT_SYSFILE_NAME "mhyprot.sys"
#define MHYPROT_SYSMODULE_NAME "mhyprot2.Sys"

#define MHYPROT_DEVICE_NAME "\\\\?\\\\mhyprot2"

#define MHYPROT_IOCTL_INITIALIZE 		0x80034000
#define MHYPROT_IOCTL_READ_KERNEL_MEMORY	0x83064000
#define MHYPROT_IOCTL_READ_WRITE_USER_MEMORY	0x81074000

#define MHYPROT_ACTION_READ	0x0
#define MHYPROT_ACTION_WRITE	0x1

#define MHYPROT_OFFSET_SEEDMAP 	0xA0E8

namespace mhyprot
{
	typedef struct _MHYPROT_INITIALIZE
	{
		DWORD		_m_001;
		DWORD		_m_002;
		DWORD64		_m_003;
	} MHYPROT_INITIALIZE, *PMHYPROT_INITIALIZE;

	typedef struct _MHYPROT_KERNEL_READ_REQUEST
	{
		union _HEADER
		{
			DWORD		result;
			DWORD64		address;
		} header;
		ULONG size;
	} MHYPROT_KERNEL_READ_REQUEST, *PMHYPROT_KERNEL_READ_REQUEST;

	typedef struct _MHYPROT_USER_READ_WRITE_REQUEST
	{
		DWORD64 random_key;
		DWORD action;
		DWORD unknown_00;
		DWORD process_id;
		DWORD unknown_01;
		DWORD64 buffer;
		DWORD64 address;
		ULONG size;
		ULONG unknown_02;
	} MHYPROT_USER_READ_WRITE_REQUEST, *PMHYPROT_USER_READ_WRITE_REQUEST;

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
		bool request_ioctl(DWORD ioctl_code, LPVOID in_buffer, DWORD in_buffer_size);
		bool driver_init(bool debug_prints = false, bool print_seeds = false);
		uint64_t generate_key(uint64_t seed);
		void encrypt_payload(void* payload, size_t size);

		bool read_kernel_memory(uint64_t address, void* buffer, size_t size);
		template<class T> __forceinline T read_kernel_memory(uint64_t address)
		{
			T buffer;
			read_kernel_memory(address, &buffer, sizeof(T));
			return buffer;
		}

		bool read_user_memory(uint32_t process_id, uint64_t address, void* buffer, size_t size);
		template<class T> __forceinline T read_user_memory(uint32_t process_id, uint64_t address)
		{
			T buffer;
			read_user_memory(process_id, address, &buffer, sizeof(T));
			return buffer;
		}

		bool write_user_memory(uint32_t process_id, uint64_t address, void* buffer, size_t size);
		template<class T> __forceinline bool write_user_memory(uint32_t process_id, uint64_t address, T value)
		{
			return write_user_memory(process_id, address, &value, sizeof(T));
		}
	}
}
