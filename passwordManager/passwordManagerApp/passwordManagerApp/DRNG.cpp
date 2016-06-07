#include "DRNG.h"
#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <string.h>
#include <intrin.h>
#include <immintrin.h>

#define DRNG_SUPPORT_UNKNOWN	-1 
#define DRNG_SUPPORT_NONE		0
#define DRNG_SUPPORT_RDRAND		0x01
#define DRNG_SUPPORT_RDSEED		0x02

#define HAVE_RDRAND ((_drng_support & DRNG_SUPPORT_RDRAND)==DRNG_SUPPORT_RDRAND)
#define HAVE_RDSEED ((_drng_support & DRNG_SUPPORT_RDSEED)==DRNG_SUPPORT_RDSEED)

#ifdef __ICL
#define COMPILER_HAS_RDSEED_SUPPORT 1
#else
#	if _MSC_VER >= 1800
#	define COMPILER_HAS_RDSEED_SUPPORT 1
#	endif
#endif

static int _drng_support= DRNG_SUPPORT_UNKNOWN;

static int _get_drng_support(int *cpuinfo);

int _get_drng_support(int info[])
{
	int rv= DRNG_SUPPORT_NONE;

	if ( memcmp(&(info[1]), "Genu", 4) || 
		memcmp(&(info[3]), "ineI", 4) ||
		memcmp(&(info[2]), "ntel", 4) ) return rv;

	__cpuidex(info, 1, 0);

	if ( ((UINT) info[2]) & (1<<30) ) rv|= DRNG_SUPPORT_RDRAND;

#ifdef COMPILER_HAS_RDSEED_SUPPORT
	__cpuidex(info, 7, 0);

	if ( ((UINT) info[1]) & (1<<18) ) rv|= DRNG_SUPPORT_RDSEED;
#endif

	return rv;
}

DRNG::DRNG(void)
{
	int info[4];
	
	if (_drng_support != DRNG_SUPPORT_UNKNOWN) return;

	// Check our feature support

	__cpuid(info, 0);

	_drng_support= _get_drng_support(info);
}

DRNG::DRNG(int *info)
{
	if (_drng_support != DRNG_SUPPORT_UNKNOWN) return;

	_drng_support= _get_drng_support(info);
}

DRNG::~DRNG(void)
{
}

int DRNG::have_rdrand ()
{
	return HAVE_RDRAND;
}

int DRNG::have_rdseed ()
{
	return HAVE_RDRAND;
}

int DRNG::random (ULONGLONG max, ULONGLONG *rand)
{
	UINT bits;
	int retries= 1000; // A big enough number make failure extremely unlikely.

	if ( ! HAVE_RDRAND ) return 0;

	if ( max == 0 ) {
		*rand= 0;
		return 1;
	}

	bits= ceiling_log2(max);

	if ( bits > 32 ) {
		ULONG64 val;

		while (retries--) {
			if ( ! rand64(&val) ) return 0;

			val>>= (64-bits);

			if ( val < max ) {
				*rand= (ULONGLONG) val;
				return 1;
			}
		}
	} else {
		ULONG32 val;

		while (retries--) {
			if ( ! rand32(&val) ) return 0;

			val>>= (32-bits);

			if ( val < max ) {
				*rand= (ULONGLONG) val;
				return 1;
			}
		}
	}

	// Keep the compiler from complaining.
	return 0;
}

ULONG DRNG::get_rand_bytes (void *buf, ULONG n)
{
	ULONG count= 0;
	BYTE rand[8];
	PBYTE pb= (PBYTE) buf;
#ifdef _WIN64
	ULONG blocks= int(n/8);

	if ( ! HAVE_RDRAND ) return 0;

	count= get_n_rand64((ULONG64 *) pb, blocks, 100*blocks);
	if ( count < blocks ) return count*8;
	else count*= 8;
	pb+= blocks*8;
#else
	ULONG blocks= int(n/4);

	count= get_n_rand32((ULONG32 *) pb, blocks, 200*blocks);
	if ( count < blocks ) return count*4;
	else count*= 4;
	pb+= blocks*4;
#endif

	if ( ! rand64((ULONG64 *) rand) ) return count;
	memcpy(pb, rand, (n-count));

	return n;
}

ULONG DRNG::get_seed_bytes (void *buf, ULONG n)
{
#ifdef COMPILER_HAS_RDSEED_SUPPORT
	ULONG count= 0;
	BYTE seed[8];
	PBYTE pb= (PBYTE) buf;
	ULONG blocks;

	if ( ! HAVE_RDSEED ) return seed_from_rdrand(buf, n);

# ifdef _WIN64
	blocks= int(n/8);
	count= get_n_seed64((ULONG64 *) pb, blocks, 100*blocks);
	if ( count < blocks ) return count*8;
	else count*= 8;
	pb+= blocks*8;
# else
	blocks= int(n/4);
	count= get_n_seed32((ULONG32 *) pb, blocks, 200*blocks);
	if ( count < blocks ) return count*4;
	else count*= 4;
	pb+= blocks*4;
# endif

	if ( ! seed64((ULONG64 *) seed) ) return count;
	memcpy(pb, seed, (n-count));

	return n;
#else
	return seed_from_rdrand(buf, n);
#endif
}

//-----------------------------------------------
// RDRAND internal methods
//-----------------------------------------------

int DRNG::rand32 (ULONG32 *rand)
{
	int retries= 10;

	if ( ! HAVE_RDRAND ) return 0;

	while (retries--) if ( _rdrand32_step(rand) ) return 1;

	return 0;
}

int DRNG::rand64 (ULONG64 *rand)
{
	int retries= 10;

	if ( ! HAVE_RDRAND ) return 0;

#ifdef _WIN64
	while (retries--) if ( _rdrand64_step(rand) ) return 1;
#else
	if ( get_n_rand32((ULONG32 *)rand, 2, 20) == 2 ) return 1;
#endif

	return 0;
}

ULONG DRNG::get_n_rand32 (ULONG32 *buf, ULONG n, ULONG retries)
{
	ULONG count= 0;

	if ( ! HAVE_RDRAND ) return 0;

	while (n) {
		if ( _rdrand32_step(buf) ) {
			--n;
			++buf;
			++count;
		} else {
			if ( ! retries ) return count;
			retries--;
		}
	}

	return count;
}

ULONG DRNG::get_n_rand64 (ULONG64 *buf, ULONG n, ULONG retries)
{
	ULONG count= 0;

	if ( ! HAVE_RDRAND ) return 0;
#ifdef _WIN64

	while (n) {
		if ( _rdrand64_step(buf) ) {
			--n;
			++buf;
			++count;
		} else {
			if ( ! retries ) return count;
			retries--;
		}
	}

	return count;
#else
	count= get_n_rand32((ULONG32 *) buf, n, retries);
	if ( count == n ) {
		count= get_n_rand32((ULONG32 *)buf+n*4, n, retries);
		if ( count == n ) return n;
		return n/2 + int(count/2);
	}

	return int(count/2);
#endif
}

//-----------------------------------------------
// RDSEED internal methods
//-----------------------------------------------

int DRNG::seed32 (ULONG32 *seed) 
{
#ifdef COMPILER_HAS_RDSEED_SUPPORT
	int retries= 100;

	if ( ! HAVE_RDSEED ) return seed_from_rdrand(seed, 4);

	while (retries--) {
		if ( _rdseed32_step(seed) ) return 1;
		_mm_pause();
	}

	return 0;
#else
	return seed_from_rdrand(seed, 4);
#endif
}

int DRNG::seed64 (ULONG64 *seed)
{
#ifdef COMPILER_HAS_RDSEED_SUPPORT
	int retries= 100;

	if ( ! HAVE_RDSEED ) return seed_from_rdrand(seed, 8);

# ifdef _WIN64
	while (retries--) {
		if ( _rdseed64_step(seed) ) return 1;
		_mm_pause();
	}
# else
	if ( get_n_seed32((ULONG32 *)seed, 2, 2*retries) == 2 ) return 1;
# endif

	return 0;
#else
	return seed_from_rdrand(seed, 8);
#endif
}

ULONG DRNG::get_n_seed32 (ULONG32 *buf, ULONG n, ULONG retries)
{
#ifdef COMPILER_HAS_RDSEED_SUPPORT
	ULONG count= 0;

	if ( ! HAVE_RDSEED ) return seed_from_rdrand(buf, 4*n);

	while (n) {
		if ( _rdseed32_step(buf) ) {
			--n;
			++buf;
			++count;
		} else {
			if ( ! retries ) return count;
			retries--;
		}
		_mm_pause();
	}

	return count;
#else
	return seed_from_rdrand(buf, 4*n);
#endif
}

ULONG DRNG::get_n_seed64 (ULONG64 *buf, ULONG n, ULONG retries)
{
#ifdef COMPILER_HAS_RDSEED_SUPPORT
	ULONG count= 0;

	if ( ! HAVE_RDSEED ) return seed_from_rdrand(buf, 8*n);

# ifdef _WIN64
	while (n) {
		if ( _rdseed64_step(buf) ) {
			--n;
			++buf;
			++count;
		} else {
			if ( ! retries ) return count;
			retries--;
		}
		_mm_pause();
	}

	return count;
# else
	count= get_n_seed32((ULONG32 *) buf, n, retries);
	if ( count == n ) {
		count= get_n_seed32((ULONG32 *)buf+n*4, n, retries);
		if ( count == n ) return n;
		return n/2 + int(count/2);
	}

	return int(count/2);
# endif
#else
	return seed_from_rdrand(buf, 8*n);
#endif
}

ULONG DRNG::seed_from_rdrand (void *buf, ULONG n)
{
	// Use CBC-MAC mode of AES to generate 128-bit seeds from RDRAND. This is expensive
	// but if we don't have RDSEED this is our only option.
	//
	// The DRNG is guaranteed to reseed after 512 128-bit samples have been generated.

	BYTE key[16], iv[16], rand[16*512];
	BCRYPT_ALG_HANDLE halgo;
	BCRYPT_KEY_HANDLE hkey;
	NTSTATUS status;
	PBYTE bp= (PBYTE) buf;
	ULONG count= 0;

	// Create an ephemeral key

	if ( get_n_rand64((ULONG64 *) key, 2, 20) != 2 ) return 0;

	// Set up encryption

	status= BCryptOpenAlgorithmProvider(&halgo, BCRYPT_AES_ALGORITHM, NULL, 0);
	if ( status != STATUS_SUCCESS ) return 0;

	status= BCryptGenerateSymmetricKey(halgo, &hkey, NULL, 0, (PBYTE) key, 16, 0);
	if ( status != STATUS_SUCCESS ) return 0;

	status= BCryptSetProperty(halgo, BCRYPT_CHAINING_MODE, (PBYTE) BCRYPT_CHAIN_MODE_CBC, 
		sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if ( status != STATUS_SUCCESS ) return 0;

	while ( n ) {
		ULONG len= 0;
		ULONG chunk= ( n >= 16 ) ? 16 : n;

		// Fill our buffer with RDRAND values.
		if ( get_n_rand64((ULONG64 *) rand, 1024, 10240) != 1024 ) {
			// Error
			goto cleanup;
		}

		// CBC-MAC mode is a CBC encryption with a 0 IV on the plaintext.
		
		status= BCryptEncrypt(hkey, (PBYTE) rand, 512*16, NULL, NULL, 0, (PBYTE) rand, 512*16, &len, 0);
		if ( status != STATUS_SUCCESS || len != 512*16 ) {
			// Error
			goto cleanup;
		}

		// The last ciphertext block is the MAC.
		memcpy(bp, &rand[511*16], chunk);
		bp+= chunk;
		n-= chunk;
		count+= chunk;
	}

cleanup:
	BCryptDestroyKey(hkey);
	BCryptCloseAlgorithmProvider(halgo, 0);

	return count;
}

// Fast ceiling of log base 2
// http://stackoverflow.com/questions/3272424/compute-fast-log-base-2-ceiling
// Question asked by: kevinlawler (http://stackoverflow.com/users/365478/kevinlawler)
// Answered by: dgobbi (http://stackoverflow.com/users/2154690/dgobbi)
// Licensed under http://creativecommons.org/licenses/by-sa/3.0/
// Changes to variable names only. [-JM]

int DRNG::ceiling_log2 (ULONGLONG n)
{
	static const ULONGLONG t[] = {
		0xFFFFFFFF00000000ull,
		0x00000000FFFF0000ull,
		0x000000000000FF00ull,
		0x00000000000000F0ull,
		0x000000000000000Cull,
		0x0000000000000002ull
	};
	int i, j, k, m;

	j= 32;
	m= (((n&(n-1))==0) ? 0 : 1);

	for (i= 0; i< 6; ++i) {
		k= (((n&t[i])==0) ? 0 : j);
		m+= k;
		n>>= k;
		j>>= 1;
	}

	return m;
}