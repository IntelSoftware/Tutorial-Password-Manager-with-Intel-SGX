// Tests for the Crypto module

#pragma comment(lib, "Bcrypt.lib")

#include "stdafx.h"
#include "windows.h"
#include "..\..\Crypto.h"
#include <stdio.h>
#include <string.h>

int test_result(int);
int test_salt(Crypto *crypto, PBYTE salt);
int test_kdf (Crypto *crypto, PBYTE passphrase, DWORD passphrase_len, PBYTE salt, PBYTE master_key);
int test_db_key(Crypto *crypto, PBYTE db_key);
int test_key_encryption(Crypto *crypto, PBYTE db_key, PBYTE master_key);

int db_key_callback(int count, int need);

void hexdump (const PBYTE data, DWORD len, BOOL addresses);
int hexval (const BYTE ch, PBYTE val);
int pack (PBYTE hex, const PBYTE ascii, ULONG len);
void Exit (int code);

static const BYTE initbytes[]= { 
	0xDE, 0xAD, 0x8B, 0xAD, 0xCA, 0xFE, 0xF0, 0x0D,  
	0xDE, 0xAD, 0x8B, 0xAD, 0xCA, 0xFE, 0xF0, 0x0D,
	0xDE, 0xAD, 0x8B, 0xAD, 0xCA, 0xFE, 0xF0, 0x0D,
	0xDE, 0xAD, 0x8B, 0xAD, 0xCA, 0xFE, 0xF0, 0x0D,
	0xDE, 0xAD, 0x8B, 0xAD, 0xCA, 0xFE, 0xF0, 0x0D,
	0xDE, 0xAD, 0x8B, 0xAD, 0xCA, 0xFE, 0xF0, 0x0D,
	0xDE, 0xAD, 0x8B, 0xAD, 0xCA, 0xFE, 0xF0, 0x0D,
	0xDE, 0xAD, 0x8B, 0xAD, 0xCA, 0xFE, 0xF0, 0x0D
};

#define PASSPHRASE "This is my test passphrase and I h0pe you like it."

int _tmain(int argc, _TCHAR* argv[])
{
	Crypto crypto;
	BYTE salt[CRYPTO_KDF_SALT_LEN];
	BYTE master_key[16], db_key[16];
	int pass= 0;
	int tests= 4;

	pass+= test_result(
		test_salt(&crypto, (PBYTE) salt)
	);

	pass+= test_result(
		test_db_key(&crypto, db_key)
	);
	
	pass+= test_result(
		test_kdf(&crypto, (PBYTE) PASSPHRASE, sizeof(PASSPHRASE), salt, master_key)
	);

	pass+= test_result(
		test_key_encryption(&crypto, db_key, master_key)
	);

	if ( tests == pass ) {
		wprintf(L"\n===> ALL TESTS PASSED <===\n\n");
		Exit(0);
	}

	wprintf(L"%d OF %d TESTS PASSING\n\n", pass, tests);
	Exit(1);
}

//----------------------------------------------------------------------------------------------------
// DB encryption/decryption test
//----------------------------------------------------------------------------------------------------

int test_key_encryption(Crypto *crypto, PBYTE db_key, PBYTE master_key)
{
	crypto_status_t status;
	BYTE tmkey[16], tdbkey[16], ekey[16], iv[12], authtag[16], kauthtag[16], ddb_key[16];
	static const BYTE ekey_answer[]= { 0x6c, 0x7e, 0xf7, 0x29, 0x15, 0xa3, 0xe8, 0x63, 0x8b, 0xc4, 0xc7, 0x2e, 0xd9, 0x2a, 0xfc, 0x35 };
	static const BYTE authtag_answer[]= { 0x88, 0xc9, 0x81, 0x29, 0xaa, 0x5a, 0x74, 0x08, 0x4d, 0xc3, 0xf5, 0x69, 0x86, 0x37, 0xa0, 0xce };

	wprintf(L"DB KEY ENCRYPTION TEST\n");

	// Known key encryption test

	memcpy(tmkey, initbytes, 16);
	if ( memcmp(tmkey, initbytes, 16) != 0 ) {
		wprintf(L"Error: Known master key initialization failed\n");
		return 0;
	}

	memcpy(tdbkey, initbytes, 16);
	if ( memcmp(tdbkey, initbytes, 16) != 0 ) {
		wprintf(L"Error: Known master key initialization failed\n");
		return 0;
	}

	memcpy(ekey, initbytes, 16);
	if ( memcmp(ekey, initbytes, 16) != 0 ) {
		wprintf(L"Error: Encrypted, known DB key initialization failed\n");
		return 0;
	}

	memcpy(iv, initbytes, 12);
	if ( memcmp(iv, initbytes, 12) != 0 ) {
		wprintf(L"Error: Known IV key initialization failed\n");
		return 0;
	}

	memcpy(authtag, initbytes, 12);
	if ( memcmp(authtag, initbytes, 12) != 0 ) {
		wprintf(L"Error: authentication tag initialization failed\n");
		return 0;
	}

	wprintf(L"Known database key:\n");
	hexdump(tdbkey, 16, 1);
	wprintf(L"Lnown master key:\n");
	hexdump(tmkey, 16, 1);
	wprintf(L"Known IV:\n");
	hexdump(iv, 12, 1);

	wprintf(L"Encrypting known database key with known master key...\n");
	status= crypto->encrypt_database_key(tmkey, tdbkey, ekey, iv, authtag, CRYPTO_F_IV_PROVIDED);
	if ( status != CRYPTO_OK ) {
		wprintf(L"encrypt_database_key returned 0x%08x\n", status);
		return 0;
	}
	wprintf(L"Encrypted, known database key:\n");
	hexdump(ekey, 16, 1);
	wprintf(L"Known auth tag:\n");
	hexdump(authtag, 16, 1);

	if ( memcmp(ekey, ekey_answer, 16) ) {
		wprintf(L"Known key encryption does not match expected answer\n");
		return 0;
	}

	if ( memcmp(authtag, authtag_answer, 16) ) {
		wprintf(L"Known key encryption auth tag does not match expected answer\n");
		return 0;
	}

	// Encrypt with provided keys and random IV

	wprintf(L"\nEncrypting provides keys with random IV\n");
	wprintf(L"Database key:\n");
	hexdump(db_key, 16, 1);
	wprintf(L"Master key:\n");
	hexdump(master_key, 16, 1);

	memcpy(kauthtag, initbytes, 12);
	if ( memcmp(kauthtag, initbytes, 12) != 0 ) {
		wprintf(L"Error: authentication tag initialization failed\n");
		return 0;
	}

	status= crypto->encrypt_database_key(master_key, db_key, ekey, iv, kauthtag);
	if ( status != CRYPTO_OK ) {
		wprintf(L"encrypt_database_key returned 0x%08x\n", status);
		return 0;
	}
	wprintf(L"Encrypted, database key:\n");
	hexdump(ekey, 16, 1);
	wprintf(L"Auth tag:\n");
	hexdump(kauthtag, 16, 1);
	wprintf(L"IV:\n");
	hexdump(iv, 12, 1);

	if ( memcmp(iv, initbytes, 12) == 0 ) {
		wprintf(L"IV not random\n");
		return 0;
	}

	// Decryption

	memcpy(ddb_key, initbytes, 16);
	if ( memcmp(ddb_key, initbytes, 16) != 0 ) {
		wprintf(L"Error: Known master key initialization failed\n");
		return 0;
	}

	wprintf(L"Decrypting encrypted master key...\n");
	status= crypto->decrypt_database_key(master_key, ekey, iv, kauthtag, ddb_key);
	if ( status != CRYPTO_OK ) {
		wprintf(L"decrypt_database_key returned 0x%08x\n", status);
		return 0;
	} else {
		wprintf(L"decrypt_database_key OK\n", status);
		hexdump(ddb_key, 16, 1);
	}

	wprintf(L"Decrypt with bad master key (should fail)...\n");
	status= crypto->decrypt_database_key(tmkey, ekey, iv, kauthtag, ddb_key);
	if ( status == CRYPTO_OK ) {
		wprintf(L"decrypt_database_key OK\n", status);
		return 0;
	}  else {
		wprintf(L"decrypt_database_key FAILED\n", status);
	}

	wprintf(L"Decrypt with bad IV (should fail)...\n");
	iv[2]^= 0xff;
	status= crypto->decrypt_database_key(master_key, ekey, iv, kauthtag, ddb_key);
	if ( status == CRYPTO_OK ) {
		wprintf(L"decrypt_database_key OK\n", status);
		return 0;
	}  else {
		wprintf(L"decrypt_database_key FAILED\n", status);
	}
	iv[2]^= 0xff;

	wprintf(L"Decrypt with bad ciphertext (should fail)...\n");
	ekey[15]^= 0xff;
	status= crypto->decrypt_database_key(master_key, ekey, iv, kauthtag, ddb_key);
	if ( status == CRYPTO_OK ) {
		wprintf(L"decrypt_database_key OK\n", status);
		return 0;
	}  else {
		wprintf(L"decrypt_database_key FAILED\n", status);
	}
	ekey[15]^= 0xff;

	wprintf(L"Decrypt with bad authtag (should fail)...\n");
	status= crypto->decrypt_database_key(master_key, ekey, iv, authtag, ddb_key);
	if ( status == CRYPTO_OK ) {
		wprintf(L"decrypt_database_key OK\n", status);
		return 0;
	}  else {
		wprintf(L"decrypt_database_key FAILED\n", status);
	}
	
	return 1;
}

//----------------------------------------------------------------------------------------------------
// Key Derivation Function test
//----------------------------------------------------------------------------------------------------

int test_kdf (Crypto *crypto, PBYTE passphrase, DWORD passphrase_len, PBYTE salt, PBYTE master_key)
{
	crypto_status_t status;
	static const BYTE tkey_answer[]= { 0xaf, 0x4d, 0x13, 0x25, 0x08, 0x21, 0xd3, 0x03, 0xfe, 0x02, 0xaf, 0xbb, 0xbe, 0x5d, 0xcc, 0xed };
	BYTE tsalt[CRYPTO_KDF_SALT_LEN];
	BYTE tkey[16];

	wprintf(L"KDF TEST\n");

	// Known key tests

	memcpy(tkey, initbytes, 16);
	if ( memcmp(tkey, initbytes, 16) != 0 ) {
		wprintf(L"Error: Known key initialization failed\n");
		return 0;
	}

	memcpy(tsalt, initbytes, CRYPTO_KDF_SALT_LEN);
	if ( memcmp(tkey, initbytes, CRYPTO_KDF_SALT_LEN) != 0 ) {
		wprintf(L"Error: Known salt initialization failed\n");
		return 0;
	}

	if ( (status= crypto->derive_master_key(passphrase, passphrase_len, tsalt, tkey)) == CRYPTO_OK ) {
		wprintf(L"Known master key: \n");
		hexdump(tkey, 16, 1);
	} else {
		wprintf(L"Error: derive_master_key returned 0x%08x\n", status);
		return 0;
	}

	wprintf(L"Expected master key: \n");
	hexdump((const PBYTE) tkey_answer, 16, 1);

	if ( memcmp(tkey, tkey_answer, 16) ) {
		wprintf(L"Known key derivation test failed\n");
		return 0;
	}
	memset(tkey, 0, 16);

	if ( (status= crypto->derive_master_key(passphrase, passphrase_len, tsalt, tkey)) == CRYPTO_OK && ! memcmp(tkey, tkey_answer, 16) ) {
		wprintf(L"Known master key validation OK\n");
	} else {
		wprintf(L"Known master key validation FAILED\n");
		return 0;
	}

	wprintf(L"Validating with bad passphrase (this should fail)...\n");
	if ( (status= crypto->derive_master_key(passphrase, passphrase_len-1, tsalt, tkey)) == CRYPTO_OK && ! memcmp(tkey, tkey_answer, 16)) {
		wprintf(L"Known master key validation OK\n");
		return 0;
	} else {
		wprintf(L"Known master key validation FAILED\n");
	}

	wprintf(L"Validating with bad salt (this should fail)...\n");
	tsalt[0]^= 0xFF;
	if ( (status= crypto->derive_master_key(passphrase, passphrase_len, tsalt, tkey)) == CRYPTO_OK && ! memcmp(tkey, tkey_answer, 16)) {
		wprintf(L"Known master key validation OK\n");
		return 0;
	} else {
		wprintf(L"Known master key validation FAILED\n");
	}
	tsalt[0]^= 0xFF;


	// Random salt, random key test

	if ( (status= crypto->derive_master_key(passphrase, passphrase_len, salt, master_key)) == CRYPTO_OK ) {
		wprintf(L"Master key: \n");
		hexdump(master_key, 16, 1);
	} else {
		wprintf(L"Error: derive_master_key returned 0x%08x\n", status);
		return 0;
	}

	if ( memcmp(tkey, master_key, 16) == 0 ) {
		wprintf(L"Salted master key matches known key\n");
		return 0;
	}

	return 1;
}

//----------------------------------------------------------------------------------------------------
// DB key generation test
//----------------------------------------------------------------------------------------------------

int test_db_key(Crypto *crypto, PBYTE db_key)
{
	BYTE tkey[16];
	crypto_status_t status;

	wprintf(L"DATABASE KEY TEST\n");

	memcpy(db_key, initbytes, 16);
	if ( memcmp(db_key, initbytes, 16) != 0 ) {
		wprintf(L"Error: database key initialization failed\n");
		return 0;
	}
	hexdump(db_key, 16, 1);

	memcpy(tkey, initbytes, 16);
	if ( memcmp(tkey, initbytes, 16) != 0 ) {
		wprintf(L"Error: database key 2 initialization failed\n");
		return 0;
	}
	hexdump(tkey, 16, 1);

	wprintf(L"Generating database key...\n");
	if ( (status= crypto->generate_database_key(db_key, &db_key_callback)) == CRYPTO_OK ) {
		wprintf(L"key: ");
		hexdump(db_key, 16, 0);
	} else {
		wprintf(L"Error: generate_database_key returned 0x%08x\n", status);
		return 0;
	}
	if ( memcmp(db_key, initbytes, 16) == 0 ) {
		wprintf(L"Error: database key matches initialization bytes\n");
		return 0;
	}
	
	wprintf(L"Generating database key 2...\n");
	if ( (status= crypto->generate_database_key(tkey, &db_key_callback)) == CRYPTO_OK ) {
		wprintf(L"key 2: ");
		hexdump(tkey, 16, 0);
	} else {
		wprintf(L"Error: generate_database_key returned 0x%08x\n", status);
		return 0;
	}
	if ( memcmp(tkey, initbytes, 16) == 0 ) {
		wprintf(L"Error: database key 2 matches initialization bytes\n");
		return 0;
	}

	if ( memcmp(db_key, tkey, 16) == 0 ) {
		wprintf(L"Error: keys not random\n");
		return 0;
	}

	return 1;
}

int db_key_callback(int count, int need)
{
	wprintf(L"...got %d of %d bytes\n", count, count);
	return 1;
}

//----------------------------------------------------------------------------------------------------
// Salt test
//----------------------------------------------------------------------------------------------------

int test_salt (Crypto *crypto, PBYTE salt)
{
	BYTE salt2[CRYPTO_KDF_SALT_LEN];
	crypto_status_t status;
	
	wprintf(L"RANDOM SALT TEST\n");

	memcpy(salt, initbytes, CRYPTO_KDF_SALT_LEN);
	if ( memcmp(salt, initbytes, CRYPTO_KDF_SALT_LEN) != 0 ) {
		wprintf(L"Error: salt initialization failed\n");
		return 0;
	}
	hexdump(salt, CRYPTO_KDF_SALT_LEN, 1);
	
	memcpy(salt2, initbytes, CRYPTO_KDF_SALT_LEN);
	if ( memcmp(salt2, initbytes, CRYPTO_KDF_SALT_LEN) != 0 ) {
		wprintf(L"Error: salt initialization failed\n");
		return 0;
	}
	hexdump(salt2, CRYPTO_KDF_SALT_LEN, 1);


	status= crypto->generate_salt((PBYTE) salt);
	if ( status == CRYPTO_OK ) {
		wprintf(L"salt: ");
		hexdump(salt, CRYPTO_KDF_SALT_LEN, 0);
	} else {
		wprintf(L"Error: generate_salt returned 0x%08x\n", status);
		return 0;
	}

	if ( memcmp(salt, initbytes, CRYPTO_KDF_SALT_LEN) == 0 ) {
		wprintf(L"Error: salt matches initialization string\n");
		return 0;
	}

	if ( (status= crypto->generate_salt(salt2)) == CRYPTO_OK ) {
		wprintf(L"salt2: ");
		hexdump(salt2, CRYPTO_KDF_SALT_LEN, 0);
	} else {
		wprintf(L"Error: generate_salt returned 0x%08x\n", status);
		return 0;
	}

	if ( memcmp(salt2, initbytes, CRYPTO_KDF_SALT_LEN) == 0 ) {
		wprintf(L"Error: salt2 matches initialization string\n");
		return 0;
	}


	if ( memcmp(salt, salt2, CRYPTO_KDF_SALT_LEN ) == 0 ) {
		wprintf(L"Error: salts not random\n");
		return 0;
	}

	return 1;
}


void Exit (int code)
{
	wprintf(L"Press ENTER to exit...");
	getchar();
	exit(code);
}

int pack (PBYTE hex, const PBYTE ascii, ULONG len)
{
	ULONG i;
	BYTE val;
	PBYTE pascii= ascii;

	if ( len%2 ) return 0;

	for (i= 0; i<len; ++i) {
		BYTE v;

		if ( hexval(*pascii, &v) ) {
			if ( i%2 ) {
				val<<= 4;
				val|= v;
				*hex= val;
				++hex;
			} else {
				val= v;
			}
		} else {
			return 0;
		}
		++pascii;
	}

	return 1;
}

int hexval (const BYTE ch, PBYTE val)
{
	if ( ch >= 0x30 && ch <= 0x39 ) {
		*val= ch-0x30;
		return 1;
	} else if ( ch >= 0x41 && ch <= 0x46 ) {
		*val= ch-0x37;
		return 1;
	} else if ( ch >= 0x61 && ch <= 0x66 ) {
		*val= ch-0x57;
		return 1;
	}

	return 0;
}

void hexdump (const PBYTE data, DWORD len, BOOL addresses)
{
	DWORD i;
    BYTE *bp = (unsigned char *)data;

    if (!len) return;

    if (addresses) wprintf(L"    0x%08lx:  ", data);

    for (i = 1; i <= len; ++i) {
		printf("%02x ", *bp++);
		if (!(i % 16)) {
			if (addresses && i != len) wprintf(L"\n    0x%08lx:  ", data+i);
			else if ( i != len ) wprintf(L"\n");
		}
		else if (!(i % 8)) printf(" ");
	}
	wprintf(L"\n");
}

int test_result (int b) {
	wprintf(L"*** Result: %s ***\n\n\n", (b) ? L"PASS" : L"FAIL");
	return (b) ? 1 : 0;
}