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

#include "stdafx.h"
#include "SGXWrapper.h"
#include <Windows.h>
#include <fcntl.h>
#include <io.h>
#include <tchar.h>
#include <sgx_urts.h>
#include <sgx_uae_service.h>

SGXWrapper::SGXWrapper ()
{
	sgx_support= SGX_SUPPORT_UNKNOWN;
	h_urts= NULL;
	h_service= NULL;
	fp_sgx_enable_device= NULL;
}

SGXWrapper::~SGXWrapper ()
{
	if ( h_urts != NULL ) FreeLibrary(h_urts);
	if ( h_service != NULL ) FreeLibrary(h_service);
}

UINT SGXWrapper::get_sgx_support ()
{
	check_sgx_support();
	return sgx_support;
}

int SGXWrapper::is_enabled ()
{
	check_sgx_support();
	return (sgx_support & (SGX_SUPPORT_YES|SGX_SUPPORT_ENABLED)) ? 1 : 0;
}

int SGXWrapper::is_supported ()
{
	check_sgx_support();
	return (sgx_support & SGX_SUPPORT_YES) ? 1 : 0;
}

int SGXWrapper::reboot_required ()
{
	check_sgx_support();
	return (sgx_support & (SGX_SUPPORT_YES|SGX_SUPPORT_REBOOT_REQUIRED)) ? 1 : 0;
}

int SGXWrapper::bios_enable_required ()
{
	check_sgx_support();
	return (sgx_support & (SGX_SUPPORT_YES|SGX_SUPPORT_ENABLE_REQUIRED)) ? 1 : 0;
}

// Private methods

void SGXWrapper::check_sgx_support ()
{
	sgx_device_status_t sgx_device_status;

	if ( sgx_support != SGX_SUPPORT_UNKNOWN ) return;

	sgx_support= SGX_SUPPORT_NO;

	// Check for the PSW

	if ( ! is_psw_installed() ) return;

	sgx_support= SGX_SUPPORT_YES;

	// Try to enable SGX

	if ( this->enable_device(&sgx_device_status) != SGX_SUCCESS ) return;
	
	// If SGX isn't enabled yet, perform the software opt-in/enable.
	
	if ( sgx_device_status != SGX_ENABLED ) {
		switch (sgx_device_status) {
		case SGX_DISABLED_REBOOT_REQUIRED:
			// A reboot is required.
			sgx_support|= SGX_SUPPORT_REBOOT_REQUIRED;
			break;
		case SGX_DISABLED_LEGACY_OS:
			// BIOS enabling is required
			sgx_support|= SGX_SUPPORT_ENABLE_REQUIRED;
			break;
		}

		return;
	}

	sgx_support|= SGX_SUPPORT_ENABLED;
}

// Is the PSW (Platform Software) installed?

int SGXWrapper::is_psw_installed ()
{
	_TCHAR *systemdir;
	UINT rv, sz;

	// Get the system directory path. Start by finding out how much space we need
	// to hold it.

	sz= GetSystemDirectory(NULL, 0);
	if ( sz == 0 ) return 0;

	systemdir= new _TCHAR[sz+1];
	rv= GetSystemDirectory(systemdir, sz);
	if ( rv == 0 || rv > sz ) return 0;

	// Set our DLL search path to just the System directory so we don't accidentally
	// load the DLLs from an untrusted path.

	if ( SetDllDirectory(systemdir) == 0 ) {
		delete systemdir;
		return 0;
	}

	delete systemdir; // No longer need this

	// Need to be able to load both of these DLLs from the System directory.

	if ( (h_service= LoadLibrary(_T("sgx_uae_service.dll"))) == NULL ) {
		return 0;
	}

	if ( (h_urts= LoadLibrary(_T("sgx_urts.dll"))) == NULL ) {
		FreeLibrary(h_service);
		h_service= NULL;
		return 0;
	} 

	load_functions();

	return 1;
}

void SGXWrapper::load_functions ()
{
	fp_sgx_enable_device= (fp_sgx_enable_device_t) GetProcAddress(h_service, "sgx_enable_device");
}

// Wrappers around SDK functions so the user doesn't have to mess with dynamic loading by hand.

sgx_status_t SGXWrapper::enable_device(sgx_device_status_t *device_status) 
{
	check_sgx_support();

	if ( fp_sgx_enable_device == NULL ) {
		return SGX_ERROR_UNEXPECTED;
	}

	return fp_sgx_enable_device(device_status);
}