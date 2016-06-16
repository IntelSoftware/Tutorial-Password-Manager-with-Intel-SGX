#include "Crypto.h"
#include <Windows.h>
#include <ntstatus.h>
#include <string.h>
#include <intrin.h>

Crypto::Crypto(void)
{
}


Crypto::~Crypto(void)
{
}

crypto_status_t Crypto::generate_database_key (BYTE key_out[16], GenerateDatabaseKeyCallback callback)
{
	ULONG count= 0;

	while ( (count= drng.get_seed_bytes(&key_out[count], 16)) < 16 ) {
		if ( callback != NULL ) {
			int rv;
			// So that the GUI can show a progress indicator, a cancel button, etc.
			rv= callback(count, 16);
			if ( rv == 0 ) {
				// A zero return value from the callback means we should abort.
				return CRYPTO_ERR_USER_CANCEL;
			}
		}
	}

	if ( callback != NULL ) callback(16, 16);
	return CRYPTO_OK;
}

crypto_status_t Crypto::derive_master_key (PBYTE passphrase, DWORD passphrase_len, BYTE salt[8], BYTE key_out[16])
{
	return this->derive_master_key_ex(passphrase, passphrase_len, (PBYTE) salt, 8, CRYPTO_KDF_ITERATIONS, key_out);
}

crypto_status_t Crypto::derive_master_key_ex (PBYTE passphrase, DWORD passphrase_len, PBYTE salt, DWORD salt_len, ULONG iterations, BYTE key_out[16])
{
	PBYTE messages[3]= { passphrase, salt, NULL };
	DWORD lengths[3]= { passphrase_len, salt_len, 0 };
	BYTE msg[32], md[32], key[32];
	ULONG i;
	crypto_status_t rv= CRYPTO_ERR_UNKNOWN;

	rv= this->sha256_multi(messages, lengths, md);
	if ( rv != CRYPTO_OK ) {
		return rv;
	}
	memcpy(key, md, 32);

	messages[1]= msg;
	lengths[1]= 32;

	for (i= 0; i< iterations; ++i) {
		int j;

		memcpy(msg, md, 32);
		rv= this->sha256_multi(messages, lengths, md);
		if ( rv != CRYPTO_OK) {			
			return rv;
		}
		
		// The compiler will optimize this
		for (j= 0; j<32; ++j) key[j]^= md[j];
	}

	memcpy(key_out, &(key[8]), 16);

	return CRYPTO_OK;
}

crypto_status_t Crypto::validate_passphrase (PBYTE passphrase, DWORD passphrase_len, BYTE salt[8], BYTE key_in[16])
{
	return this->validate_passphrase_ex(passphrase, passphrase_len, (PBYTE) salt, CRYPTO_KDF_SALT_LEN, CRYPTO_KDF_ITERATIONS, key_in);
}

crypto_status_t Crypto::validate_passphrase_ex (PBYTE passphrase, DWORD passphrase_len, PBYTE salt, DWORD salt_len, ULONG iterations, BYTE key_in[16])
{
	BYTE key[16];
	crypto_status_t rv= CRYPTO_ERR_UNKNOWN;

	rv= this->derive_master_key_ex(passphrase, passphrase_len, salt, salt_len, iterations, key);
	if ( rv != CRYPTO_OK ) {		
		return rv;
	}

	if ( memcmp((const char *) key, (const char *) key_in, 16) == 0 ) return CRYPTO_OK;

	// Error. They don't match.

	return CRYPTO_ERR_PASS_MISMATCH;
}

crypto_status_t Crypto::generate_salt (BYTE salt[8])
{
	return this->generate_salt_ex(salt, CRYPTO_KDF_SALT_LEN);
}

crypto_status_t Crypto::generate_salt_ex (BYTE *salt, ULONG salt_len)
{
	ULONG n= drng.get_rand_bytes(salt, salt_len);
	if ( n != salt_len ) {
		// RDRAND should not fail unless something bad has happened.
		return CRYPTO_ERR_DRNG;
	}

	return CRYPTO_OK;
}

crypto_status_t Crypto::generate_nonce_gcm (BYTE *nonce)
{
	ULONG n= drng.get_rand_bytes(nonce, 12);
	if ( n != 12 ) {
		// RDRAND should not fail unless something bad has happened.
		return CRYPTO_ERR_DRNG;
	}

	return CRYPTO_OK;
}

crypto_status_t Crypto::encrypt_database_key (BYTE master_key[16], BYTE db_key_pt[16], BYTE db_key_ct[16], BYTE iv[12], BYTE tag[16], DWORD flags)
{
	crypto_status_t rv;
	
	if ( ! (flags & CRYPTO_F_IV_PROVIDED) ) {
		rv= this->generate_nonce_gcm(iv);
		if ( rv != CRYPTO_OK ) {
			return rv;
		}
	}

	return this->aes_128_gcm_encrypt(master_key, iv, 12, db_key_pt, 16, db_key_ct, 16, tag, 16);
}

crypto_status_t Crypto::decrypt_database_key (BYTE master_key[16], BYTE db_key_ct[16], BYTE iv[12], BYTE tag[16], BYTE db_key_pt[16])
{
	return this->aes_128_gcm_decrypt(master_key, iv, 12, db_key_ct, 16, db_key_pt, 16, tag, 16);
}

crypto_status_t Crypto::encrypt_account_password (BYTE db_key[16], PBYTE password_pt, ULONG password_len, PBYTE password_ct, BYTE iv[12], BYTE tag[16], DWORD flags)
{
	crypto_status_t rv;
	
	if ( ! (flags & CRYPTO_F_IV_PROVIDED) ) {
		rv= this->generate_nonce_gcm(iv);
		if ( rv != CRYPTO_OK ) {
			return rv;
		}
	}

	return this->aes_128_gcm_encrypt(db_key, iv, 12, password_pt, password_len, password_ct, password_len, tag, 16);
}

crypto_status_t Crypto::decrypt_account_password (BYTE db_key[16], PBYTE password_ct, ULONG password_len, BYTE iv[12], BYTE tag[16], PBYTE password)
{
	return this->aes_128_gcm_decrypt(db_key, iv, 12, password_ct, password_len, password, password_len, tag, 16);
}

crypto_status_t Crypto::encrypt_database (BYTE db_key[16], PBYTE db_serialized, ULONG db_size, PBYTE db_ct, BYTE iv[12], BYTE tag[16], DWORD flags)
{
	crypto_status_t rv;
	
	if ( ! (flags & CRYPTO_F_IV_PROVIDED) ) {
		rv= this->generate_nonce_gcm(iv);
		if ( rv != CRYPTO_OK ) {
			return rv;
		}
	}

	return this->aes_128_gcm_encrypt(db_key, iv, 12, db_serialized, db_size, db_ct, db_size, tag, 16);
}

crypto_status_t Crypto::decrypt_database (BYTE db_key[16], PBYTE db_ct, ULONG db_size, BYTE iv[12], BYTE tag[16], PBYTE db_serialized)
{
	return this->aes_128_gcm_decrypt(db_key, iv, 12, db_ct, db_size, db_serialized, db_size, tag, 16);
}

crypto_status_t Crypto::aes_init (BCRYPT_ALG_HANDLE *halgo, LPCWSTR algo_id, PBYTE chaining_mode, 
					  DWORD chaining_mode_len, BCRYPT_KEY_HANDLE *hkey, PBYTE key, ULONG key_len)
{
	NTSTATUS status;

	status= BCryptOpenAlgorithmProvider(halgo, algo_id, NULL, 0);
	if ( status != STATUS_SUCCESS ) {
		// Error
		return CRYPTO_ERR_OPEN_PROVIDER;
	}

	if ( chaining_mode != NULL ) {
		status= BCryptSetProperty(*halgo, BCRYPT_CHAINING_MODE, chaining_mode, chaining_mode_len, 0);
		if ( status != STATUS_SUCCESS ) {
			// Error
			BCryptCloseAlgorithmProvider(*halgo, 0);
			return CRYPTO_ERR_SET_PROP;
		}
	}

	status= BCryptGenerateSymmetricKey(*halgo, hkey, NULL, 0, key, key_len, 0);
	if ( status != STATUS_SUCCESS ) {
		// Error
		BCryptCloseAlgorithmProvider(*halgo, 0);
		return CRYPTO_ERR_SET_KEY;
	}

	return CRYPTO_OK;
}

void Crypto::aes_close (BCRYPT_ALG_HANDLE *halgo, BCRYPT_KEY_HANDLE *hkey)
{
	if ( *halgo != NULL ) BCryptCloseAlgorithmProvider(*halgo, 0);
	if ( *hkey != NULL ) BCryptDestroyKey(*hkey);
}

// Assumes the counter is kept in the low 64 bits.

crypto_status_t Crypto::aes_128_ctr_encrypt(PBYTE key, PBYTE nonce_in, ULONG nonce_len, PBYTE pt, DWORD pt_len, PBYTE ct)
{
	BCRYPT_ALG_HANDLE halgo= NULL;
	BCRYPT_KEY_HANDLE hkey= NULL;
	ULONG blocks= pt_len/16 + ((pt_len%16) ? 1 : 0);
	ULONG rem= pt_len;
	ULONG i, j, len;
	PBYTE ppt= pt;
	PBYTE pct= ct;
	BYTE nonce[16]= { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	NTSTATUS status;
	ULONGLONG ctr= 0;
	crypto_status_t rv= CRYPTO_ERR_UNKNOWN;

	rv= this->aes_init(&halgo, BCRYPT_AES_ALGORITHM, NULL, 0, &hkey, key, 16);
	if ( rv != CRYPTO_OK ) {		
		return rv;
	}

	memcpy(nonce, nonce_in, nonce_len);

	for (i= 0; i<blocks; ++i) {
		ULONG chunk= (rem >= 16) ? 16 : rem;

		status= BCryptEncrypt(hkey, nonce, 16, NULL, NULL, 0, pct, 16, &len, 0);
		if ( status != STATUS_SUCCESS || len != 16 ) {
			rv= CRYPTO_ERR_ENCRYPT;
			goto cleanup;
		}
		
		for(j= 0; j< chunk; ++j) {
			pct[j]^= ppt[j];
		}
		ppt+= chunk;
		pct+= chunk;
		++ctr;

		memcpy(&ctr, &nonce[8], 8);
		ctr= _byteswap_uint64(ctr);
		++ctr;
		ctr= _byteswap_uint64(ctr);
		memcpy(&nonce[8], &ctr, 8);
	}

	memcpy(nonce_in, nonce, 16);

	rv= CRYPTO_OK;

cleanup:
	this->aes_close(&halgo, &hkey);

	return rv;
}

crypto_status_t Crypto::aes_128_gcm_encrypt(PBYTE key, PBYTE nonce, ULONG nonce_len, PBYTE pt, DWORD pt_len, PBYTE ct, DWORD ct_sz, PBYTE tag, DWORD tag_len)
{
	BCRYPT_ALG_HANDLE halgo= NULL;
	BCRYPT_KEY_HANDLE hkey= NULL;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authinfo;
	NTSTATUS status;
	DWORD ct_len;
	crypto_status_t rv= CRYPTO_ERR_UNKNOWN;

	rv= this->aes_init(&halgo, BCRYPT_AES_ALGORITHM, (PBYTE) BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), &hkey, key, 16);
	if ( rv != CRYPTO_OK ) {
		return rv;
	}

	BCRYPT_INIT_AUTH_MODE_INFO(authinfo);
	authinfo.pbNonce= &nonce[0];
	authinfo.cbNonce= nonce_len;
	authinfo.pbTag= &tag[0];
	authinfo.cbTag= tag_len;

	status= BCryptEncrypt(hkey, pt, pt_len, (PBYTE) &authinfo, NULL, 0, ct, ct_sz, &ct_len, 0);
	if ( status != STATUS_SUCCESS ) {
		rv= CRYPTO_ERR_ENCRYPT;
	} else {
		rv= CRYPTO_OK;
	}

cleanup:
	this->aes_close(&halgo, &hkey);

	return rv;
}

crypto_status_t Crypto::aes_128_gcm_decrypt(PBYTE key, PBYTE nonce, ULONG nonce_len, PBYTE ct, DWORD ct_len, PBYTE pt, DWORD pt_sz, PBYTE tag, DWORD tag_len)
{
	BCRYPT_ALG_HANDLE halgo= NULL;
	BCRYPT_KEY_HANDLE hkey= NULL;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authinfo;
	NTSTATUS status;
	DWORD pt_len;
	crypto_status_t rv= CRYPTO_ERR_UNKNOWN;

	rv= this->aes_init(&halgo, BCRYPT_AES_ALGORITHM, (PBYTE) BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), &hkey, key, 16);
	if ( rv != CRYPTO_OK ) {
		return rv;
	}

	BCRYPT_INIT_AUTH_MODE_INFO(authinfo);
	authinfo.pbNonce= &nonce[0];
	authinfo.cbNonce= nonce_len;
	authinfo.pbTag= &tag[0];
	authinfo.cbTag= tag_len;

	status= BCryptDecrypt(hkey, ct, ct_len, (PBYTE) &authinfo, NULL, 0, pt, pt_sz, &pt_len, 0);
	if ( status != STATUS_SUCCESS ) {
		if ( status == STATUS_AUTH_TAG_MISMATCH ) rv= CRYPTO_ERR_DECRYPT_AUTH;
		else rv= CRYPTO_ERR_DECRYPT;
	} else {
		rv= CRYPTO_OK;
	}

cleanup:
	this->aes_close(&halgo, &hkey);

	return rv;
}

crypto_status_t Crypto::sha256 (PBYTE message, ULONG message_length, BYTE md[32])
{
	PBYTE messages[2]= { message, NULL };
	ULONG lengths[2]= { message_length, 0 };

	return this->sha256_multi(messages, lengths, md);
}

crypto_status_t Crypto::sha256_multi (PBYTE *messages, ULONG *lengths, BYTE md[32])
{
	BCRYPT_ALG_HANDLE halgo= NULL;
	BCRYPT_HASH_HANDLE hhash= NULL;
	NTSTATUS status;
	DWORD hashobjlen= 310; //Size for SHA-256
	crypto_status_t rv= CRYPTO_ERR_UNKNOWN;
	BYTE hashobject[310]; //Size for SHA-256
	PBYTE *message= messages;
	ULONG *length= lengths;
	DWORD result= 0;

	status= BCryptOpenAlgorithmProvider(&halgo, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	if ( status != STATUS_SUCCESS ) {
		return CRYPTO_ERR_OPEN_PROVIDER;
	}

	status = BCryptCreateHash(halgo, &hhash, hashobject, hashobjlen, NULL, 0, 0);
	if ( status != STATUS_SUCCESS ) {
		BCryptCloseAlgorithmProvider(halgo, 0);
		return CRYPTO_ERR_CREATE_HASH;
	}

	while ( *message != NULL ) {
		status= BCryptHashData(hhash, *message, *length, 0);
		if ( status != STATUS_SUCCESS ) {
			rv= CRYPTO_ERR_HASH_DATA;
			goto cleanup;
		}
		++message;
		++length;
	}

	status= BCryptFinishHash(hhash, md, 32, 0);
	if ( status != STATUS_SUCCESS ) {
		rv= CRYPTO_ERR_FINISH_HASH;
	} else {
		rv= CRYPTO_OK;
	}

cleanup:
	BCryptDestroyHash(hhash);
	BCryptCloseAlgorithmProvider(halgo, 0);

	return rv;
}
