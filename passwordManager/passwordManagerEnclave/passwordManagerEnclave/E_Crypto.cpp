#include "E_Crypto.h"
#include <sgx_tcrypto.h>
#include <string.h>

static void _xor_quads (void *dst, void *src, int n);

E_Crypto::E_Crypto(void)
{
}


E_Crypto::~E_Crypto(void)
{
}

crypto_status_t E_Crypto::generate_database_key (unsigned char key_out[16], GenerateDatabaseKeyCallback callback)
{
	unsigned long count= 0;

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

crypto_status_t E_Crypto::derive_master_key (unsigned char *passphrase, unsigned long passphrase_len, unsigned char salt[8], unsigned char key_out[16])
{
	return this->derive_master_key_ex(passphrase, passphrase_len, salt, 8, CRYPTO_KDF_ITERATIONS, key_out);
}

crypto_status_t E_Crypto::derive_master_key_ex (unsigned char *passphrase, unsigned long passphrase_len, unsigned char *salt, unsigned long salt_len,
	unsigned long iterations, unsigned char key_out[16])
{
	unsigned char *messages[3]= { passphrase, salt, NULL };
	unsigned long lengths[3]= { passphrase_len, salt_len, 0 };
	unsigned char msg[32], md[32], key[32];
	unsigned long i;
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

crypto_status_t E_Crypto::validate_passphrase (unsigned char *passphrase, unsigned long passphrase_len, unsigned char salt[8], unsigned char key_in[16])
{
	return this->validate_passphrase_ex(passphrase, passphrase_len, salt, CRYPTO_KDF_SALT_LEN, CRYPTO_KDF_ITERATIONS, key_in);
}

crypto_status_t E_Crypto::validate_passphrase_ex (unsigned char *passphrase, unsigned long passphrase_len, unsigned char *salt, unsigned long salt_len,
	unsigned long iterations, unsigned char key_in[16])
{
	unsigned char key[16];
	crypto_status_t rv= CRYPTO_ERR_UNKNOWN;

	rv= this->derive_master_key_ex(passphrase, passphrase_len, salt, salt_len, iterations, key);
	if ( rv != CRYPTO_OK ) {		
		return rv;
	}

	if ( memcmp((const char *) key, (const char *) key_in, 16) == 0 ) return CRYPTO_OK;

	// Error. They don't match.

	return CRYPTO_ERR_PASS_MISMATCH;
}

crypto_status_t E_Crypto::generate_salt (unsigned char salt[8])
{
	return this->generate_salt_ex(salt, CRYPTO_KDF_SALT_LEN);
}

crypto_status_t E_Crypto::generate_salt_ex (unsigned char *salt, unsigned long salt_len)
{
	unsigned long n= drng.get_rand_bytes(salt, salt_len);
	if ( n != salt_len ) {
		// RDRAND should not fail unless something bad has happened.
		return CRYPTO_ERR_DRNG;
	}

	return CRYPTO_OK;
}

crypto_status_t E_Crypto::generate_nonce_gcm (unsigned char *nonce)
{
	unsigned long n= drng.get_rand_bytes(nonce, 12);
	if ( n != 12 ) {
		// RDRAND should not fail unless something bad has happened.
		return CRYPTO_ERR_DRNG;
	}

	return CRYPTO_OK;
}

crypto_status_t E_Crypto::encrypt_database_key (unsigned char master_key[16], unsigned char db_key_pt[16], unsigned char db_key_ct[16],
	unsigned char iv[12], unsigned char tag[16], unsigned int flags)
{
	crypto_status_t rv;

	
	if ( ! (flags & CRYPTO_F_IV_PROVIDED) ) {
		rv= this->generate_nonce_gcm(iv);
		if ( rv != CRYPTO_OK ) {
			return rv;
		}
	}

	return this->aes_128_gcm_encrypt(master_key, iv, 12, db_key_pt, 16, db_key_ct, tag);
}

crypto_status_t E_Crypto::decrypt_database_key (unsigned char master_key[16], unsigned char db_key_ct[16], unsigned char iv[12],
	unsigned char tag[16], unsigned char db_key_pt[16])
{
	return this->aes_128_gcm_decrypt(master_key, iv, 12, db_key_ct, 16, db_key_pt, tag);
}

crypto_status_t E_Crypto::encrypt_account_password (unsigned char db_key[16], unsigned char *password_pt, unsigned long password_len,
	unsigned char *password_ct, unsigned char iv[12], unsigned char tag[16], unsigned int flags)
{
	crypto_status_t rv;
	
	if ( ! (flags & CRYPTO_F_IV_PROVIDED) ) {
		rv= this->generate_nonce_gcm(iv);
		if ( rv != CRYPTO_OK ) {
			return rv;
		}
	}

	return this->aes_128_gcm_encrypt(db_key, iv, 12, password_pt, password_len, password_ct, tag);
}

crypto_status_t E_Crypto::decrypt_account_password (unsigned char db_key[16], unsigned char *password_ct, unsigned long password_len,
	unsigned char iv[12], unsigned char tag[16], unsigned char *password)
{
	return this->aes_128_gcm_decrypt(db_key, iv, 12, password_ct, password_len, password, tag);
}

crypto_status_t E_Crypto::encrypt_database (unsigned char db_key[16], unsigned char *db_serialized, unsigned long db_size,
	unsigned char *db_ct, unsigned char iv[12], unsigned char tag[16], unsigned int flags)
{
	crypto_status_t rv;
	
	if ( ! (flags & CRYPTO_F_IV_PROVIDED) ) {
		rv= this->generate_nonce_gcm(iv);
		if ( rv != CRYPTO_OK ) {
			return rv;
		}
	}

	return this->aes_128_gcm_encrypt(db_key, iv, 12, db_serialized, db_size, db_ct, tag);
}

crypto_status_t E_Crypto::decrypt_database (unsigned char db_key[16], unsigned char *db_ct, unsigned long db_size,
	unsigned char iv[12], unsigned char tag[16], unsigned char *db_serialized)
{
	return this->aes_128_gcm_decrypt(db_key, iv, 12, db_ct, db_size, db_serialized, tag);
}

//------------------------------------------------------------
// Private methods 
//------------------------------------------------------------

crypto_status_t E_Crypto::aes_128_gcm_encrypt(unsigned char *key, unsigned char *nonce, unsigned long nonce_len,
		unsigned char *pt, unsigned long pt_len, unsigned char *ct, unsigned char *tag)
{
	sgx_status_t status;

	status= sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t *) key, pt, pt_len, ct, nonce, nonce_len, NULL, 0, (sgx_aes_gcm_128bit_tag_t *) tag);
	if ( status != SGX_SUCCESS ) {
		return CRYPTO_ERR_ENCRYPT;
	}

	return CRYPTO_OK;
}

crypto_status_t E_Crypto::aes_128_gcm_decrypt(unsigned char *key, unsigned char *nonce, unsigned long nonce_len,
		unsigned char *ct, unsigned long ct_len, unsigned char *pt, unsigned char *tag)
{
	sgx_status_t status;

	status= sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t *) key, ct, ct_len, pt, nonce, nonce_len, NULL, 0, (sgx_aes_gcm_128bit_tag_t *) tag);
	if ( status != SGX_SUCCESS ) {
		if ( status == SGX_ERROR_MAC_MISMATCH ) return CRYPTO_ERR_DECRYPT_AUTH;
		return CRYPTO_ERR_DECRYPT;
	}

	return CRYPTO_OK;
}


crypto_status_t E_Crypto::sha256_multi (unsigned char **messages, unsigned long *lengths, unsigned char hash[32])
{
	sgx_status_t status;
	sgx_sha_state_handle_t hsha;
	unsigned char **message= messages;
	unsigned long *length= lengths;
	crypto_status_t rv= CRYPTO_ERR_UNKNOWN;

	status= sgx_sha256_init(&hsha);
	if ( status != SGX_SUCCESS ) {
		return CRYPTO_ERR_CREATE_HASH;
	}

	while ( *message != NULL ) {
		status= sgx_sha256_update(*message, *length, hsha);
		if ( status != SGX_SUCCESS ) {
			rv= CRYPTO_ERR_HASH_DATA;
			goto cleanup;
		}
		++message;
		++length;
	}

	status= sgx_sha256_get_hash(hsha, (sgx_sha256_hash_t *) hash);
	if ( status != SGX_SUCCESS ) {
		rv= CRYPTO_ERR_FINISH_HASH;
		goto cleanup;
	}

	rv= CRYPTO_OK;

cleanup:
	sgx_sha256_close(hsha);

	return rv;
}
