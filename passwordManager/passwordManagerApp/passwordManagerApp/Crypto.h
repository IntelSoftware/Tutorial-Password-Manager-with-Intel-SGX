#pragma once

#include <Windows.h>
#include <bcrypt.h>

#include "DRNG.h"

#define CRYPTO_KDF_ITERATIONS	50000
#define CRYPTO_KDF_SALT_LEN	8

#define CRYPTO_OK						0x00000000
#define CRYPTO_ERR_OPEN_PROVIDER		0x10000001
#define CRYPTO_ERR_CREATE_HASH			0x10000002
#define CRYPTO_ERR_HASH_DATA			0x10000003
#define CRYPTO_ERR_FINISH_HASH			0x10000004
#define CRYPTO_ERR_SET_PROP				0x10000005
#define CRYPTO_ERR_GET_PROP				0x10000006
#define CRYPTO_ERR_SET_KEY				0x10000007

#define CRYPTO_ERR_DECRYPT				0x10000010
#define CRYPTO_ERR_DECRYPT_AUTH			0x10000011
#define CRYPTO_ERR_ENCRYPT				0x10000012

#define CRYPTO_ERR_PASS_MISMATCH		0x10000100
#define CRYPTO_ERR_USER_CANCEL			0x10000101

#define CRYPTO_ERR_DRNG					0x20000001

#define CRYPTO_ERR_UNKNOWN				0xF0000001

#define CRYPTO_F_IV_PROVIDED			0x00000001

typedef int (*GenerateDatabaseKeyCallback)(int, int);
typedef ULONG crypto_status_t;

class Crypto
{
	DRNG drng;

	crypto_status_t aes_init (BCRYPT_ALG_HANDLE *halgo, LPCWSTR algo_id, PBYTE chaining_mode, DWORD chaining_mode_len, BCRYPT_KEY_HANDLE *hkey, PBYTE key, ULONG key_len);
	void aes_close (BCRYPT_ALG_HANDLE *halgo, BCRYPT_KEY_HANDLE *hkey);
		
	crypto_status_t aes_128_gcm_encrypt(PBYTE key, PBYTE nonce, ULONG nonce_len, PBYTE pt, DWORD pt_len, PBYTE ct, DWORD ct_sz, PBYTE tag, DWORD tag_len);
	crypto_status_t aes_128_gcm_decrypt(PBYTE key, PBYTE nonce, ULONG nonce_len, PBYTE ct, DWORD ct_len, PBYTE pt, DWORD pt_sz, PBYTE tag, DWORD tag_len);
	crypto_status_t aes_128_ctr_encrypt(PBYTE key, PBYTE nonce, ULONG nonce_len, PBYTE pt, DWORD pt_len, PBYTE ct);
	crypto_status_t sha256 (PBYTE message, DWORD message_len, BYTE hash[32]);
	crypto_status_t sha256_multi (PBYTE *messages, ULONG *lengths, BYTE hash[32]);

public:
	Crypto(void);
	~Crypto(void);

	crypto_status_t generate_database_key (BYTE key_out[16], GenerateDatabaseKeyCallback callback);
	crypto_status_t generate_salt (BYTE salt[8]);
	crypto_status_t generate_salt_ex (PBYTE salt, ULONG salt_len);
	crypto_status_t generate_nonce_gcm (BYTE nonce[12]);

	crypto_status_t derive_master_key (PBYTE passphrase, ULONG passphrase_len, BYTE salt[8], BYTE key_out[16]);
	crypto_status_t derive_master_key_ex (PBYTE passphrase, ULONG passphrase_len, PBYTE salt, ULONG salt_len, ULONG iterations, BYTE key_out[16]);
	crypto_status_t validate_master_key (PBYTE passphrase, ULONG passphrase_len, BYTE salt[8], BYTE key_in[16]);
	crypto_status_t validate_master_key_ex (PBYTE passphrase, ULONG passphrase_len, PBYTE salt, ULONG salt_len, ULONG iterations, BYTE key_in[16]);

	crypto_status_t encrypt_master_key (BYTE master_key[16], BYTE db_key_pt[16], BYTE db_key_ct[16], BYTE iv[12], BYTE tag[16], DWORD flags= 0);
	crypto_status_t decrypt_master_key (BYTE master_key[16], BYTE db_key_ct[16], BYTE iv[12], BYTE tag[12], BYTE db_key_pt[16]);
};

