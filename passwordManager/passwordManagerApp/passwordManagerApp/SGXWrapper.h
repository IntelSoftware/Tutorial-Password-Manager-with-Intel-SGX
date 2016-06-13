// Copyright 2016 Intel Corporation.
//
// The source code, information and material ("Material") contained herein is owned by
// Intel Corporation or its suppliers or licensors, and title to such Material remains
// with Intel Corporation or its suppliers or licensors. The Material contains
// proprietary information of Intel or its suppliers and licensors. The Material is
// protected by worldwide copyright laws and treaty provisions. No part of the
// Material may be used, copied, reproduced, modified, published, uploaded, posted,
// transmitted, distributed or disclosed in any way without Intel's prior express
// written permission. No license under any patent, copyright or other intellectual
// property rights in the Material is granted to or conferred upon you, either
// expressly, by implication, inducement, estoppel or otherwise. Any license under
// such intellectual property rights must be express and approved by Intel in writing.
//
// Unless otherwise agreed by Intel in writing, you may not remove or alter this
// notice or any other notice embedded in Materials by Intel or Intel's suppliers or
// licensors in any way.

#pragma once

#include <windows.h>
#include <sgx.h>
#include <sgx_uae_service.h>
#include <sgx_urts.h>


#define SGX_SUPPORT_UNKNOWN			0x00000000
#define SGX_SUPPORT_NO				0x80000000
#define SGX_SUPPORT_YES				0x00000001
#define SGX_SUPPORT_ENABLED			0x00000002
#define SGX_SUPPORT_REBOOT_REQUIRED	0x00000004
#define SGX_SUPPORT_ENABLE_REQUIRED	0x00000008

// Needed for dynamic loading sanity

typedef sgx_status_t (SGXAPI *fp_sgx_enable_device_t)(sgx_device_status_t *);

class SGXWrapper;
typedef class SGXWrapper SGXWrapper;

class SGXWrapper {
private:
	UINT sgx_support;
	HINSTANCE h_urts, h_service;

	// Function pointers

	fp_sgx_enable_device_t fp_sgx_enable_device;

	int is_psw_installed (void);
	void check_sgx_support (void);
	void load_functions (void);

public:
	SGXWrapper();
	~SGXWrapper();

	UINT get_sgx_support (void);
	int is_enabled (void);
	int is_supported (void);
	int reboot_required (void);
	int bios_enable_required (void);

	// Wrappers around SGX functions

	sgx_status_t enable_device(sgx_device_status_t *device_status);

};
