#include "Enclave1_t.h"
#include "sgx_trts.h"
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_LEN 100
char enclaveString[MAX_BUF_LEN] = "Internal enclave string is not initialized";

/*
Decsription: This function demonstrates the use of an 'out' enclave by 
   changing the value of an externally provided input parameter. Data 
   is sent from the enclave to the application
*/
void enclaveOutFunction(char *buf, size_t len)
{	 
	if(len < MAX_BUF_LEN)
		buf = (char*)malloc(MAX_BUF_LEN);

	memcpy(buf,enclaveString,strlen(enclaveString)+1);
	/*
	const char *secret = "Hello Enclave!"; 
	if(len > strlen(secret))
	{
		memcpy(buf,secret,strlen(secret)+1);
	}
	*/
}

/*
Decsription: This function demonstrates the use of an 'in' enclave by 
   using external/non-enclave variable to set an internal/enclave value.
   Data is sent from the application into the enclave.
*/
void enclaveInFunction(char *buf, size_t len)
{	 
	if(len <= (size_t)MAX_BUF_LEN)
		memcpy(enclaveString,buf,strlen(buf)+1);		
}

/*
Decsription: This function demonstrates the use of both an 'in' and 'out' 
   enclave by swapping the values of the input string and the internal 
   enclave string. Data is exchanged between the application and enclave.
*/
void enclaveInOutFunction(char *buf, size_t len)
{	 
	//if(strlen(buf) <= MAX_BUF_LEN)
	{
		char *tmp = (char*)malloc(MAX_BUF_LEN*sizeof(char));
		memcpy(tmp,buf,strlen(buf)+1);
		memcpy(buf,enclaveString,strlen(enclaveString)+1);
		memcpy(enclaveString,tmp,strlen(tmp)+1);
		free(tmp);
	}
}