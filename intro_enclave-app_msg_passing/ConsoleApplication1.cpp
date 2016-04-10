
#include "stdafx.h"
#include "sgx_urts.h"
#include "Enclave1_u.h"
#include <stdio.h>
#include "sgx_capable.h"
#include "sgx_uae_service.h"

#define ENCLAVE_FILE _T("Enclave1.signed.dll")
#define MAX_BUF_LEN 100


int main()
{

	sgx_enclave_id_t enclaveId = NULL;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = {0};
	sgx_launch_token_t *launchToken = NULL;
	int updated, i=0;
	char buffer[MAX_BUF_LEN] = "Initial string, before enclave calls";

	if(sgx_is_capable(&updated) != SGX_ENABLED) 
	{
		printf("Error %#x: SGX is not enabled on this device\n", ret);
		return -1;
	}

	printf("%i: %s\n", i++, buffer);

	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, 
		&enclaveId, NULL);
	if(ret != SGX_SUCCESS)
	{
		printf("Error %#x: cannot create enclave\n", ret);
		return -1;
	}
	
	enclaveOutFunction(enclaveId, buffer, MAX_BUF_LEN);
	printf("%i: %s\n", i++, buffer);

	//set the internal enclave function
	strcpy_s(buffer,"Changed the enclave string");
	enclaveInFunction(enclaveId, buffer, MAX_BUF_LEN);

	//swap values with enclave string
	strcpy_s(buffer,"New value application string");
	enclaveInOutFunction(enclaveId, buffer, MAX_BUF_LEN);

	//now, buffer should be "Changed the enclave string"
	printf("%i: %s\n", i++, buffer);

	//swap again; next output should be "New value for application string"
	enclaveInOutFunction(enclaveId, buffer, MAX_BUF_LEN);
	printf("%i: %s\n", i++, buffer);

	//grab the pre-swapped string "Changed the enclave string"
	enclaveOutFunction(enclaveId, buffer, MAX_BUF_LEN);
	printf("%i: %s\n", i++, buffer);


	if(sgx_destroy_enclave(enclaveId) != SGX_SUCCESS)
	{
		printf("Error %x: cant destroy enclave\n", ret);
		return -1;
	}
	else printf("DONE\n");
	getchar();

	/*
	Final output should be:
		0: Initial string, before enclave calls
		1: Internal enclave string is not initialized
		2: Changed the enclave string
		3: New value application string
		4: Changed the enclave string
		DONE
	*/
	return 0;
}

