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
#include <string>

#include "logger.hpp"
#include "win_utils.hpp"
#include "mhyprot.hpp"

#define CHECK_SC_MANAGER_HANDLE(x, ret_type)												\
if (!CHECK_HANDLE(x))																		\
{																							\
	logger::log("[!] failed to obtain service manager handle. (0x%lX)\n", GetLastError());	\
	return ret_type;																		\
}																							\

namespace service_utils
{
	SC_HANDLE open_sc_manager();

	SC_HANDLE create_service(const std::string_view driver_path);
	bool delete_service(SC_HANDLE service_handle, bool close_on_fail = true, bool close_on_success = true);

	bool start_service(SC_HANDLE service_handle);
	bool stop_service(SC_HANDLE service_handle);
}