#include "E_DRNG.h"
#include <sgx.h>
#include <sgx_trts.h>
#include <sgx_cpuid.h>
#include <sgx_tcrypto.h>
#include <string.h>

#define DRNG_SUPPORT_UNKNOWN	-1 
#define DRNG_SUPPORT_NONE		0
#define DRNG_SUPPORT_RDSEED		0x02

typedef unsigned long ULONG;
typedef uint32_t ULONG32;
typedef uint64_t ULONG64;
typedef unsigned long long ULONGLONG;
typedef unsigned int UINT;

// This is all we need since the SGX SDK takes care of RDRAND support

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

#ifdef COMPILER_HAS_RDSEED_SUPPORT
	__cpuidex(info, 7, 0);

	if ( ((UINT) info[1]) & (1<<18) ) rv|= DRNG_SUPPORT_RDSEED;
#endif

	return rv;
}

E_DRNG::E_DRNG(void)
{
	int info[4];
	sgx_status_t status;
	
	if (_drng_support != DRNG_SUPPORT_UNKNOWN) return;

	// Check for RDSEED support

	status= sgx_cpuidex(info, 1, 0);
	if ( status == SGX_SUCCESS ) {
		_drng_support= _get_drng_support(info);
	}
}

E_DRNG::~E_DRNG(void)
{
}

int E_DRNG::have_rdseed ()
{
	return HAVE_RDSEED;
}

int E_DRNG::random (ULONGLONG max, ULONGLONG *rand)
{
	UINT bits;
	int retries= 1000; // A big enough number make failure extremely unlikely.

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

ULONG E_DRNG::get_rand_bytes (void *buf, ULONG n)
{
	if ( sgx_read_rand((unsigned char *) buf, n) == SGX_SUCCESS ) return n;

	return 0;
}

ULONG E_DRNG::get_seed_bytes (void *buf, ULONG n)
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

int E_DRNG::rand32 (ULONG32 *rand)
{
	int retries= 10;

	while (retries--) if ( sgx_read_rand((unsigned char *) rand, 4) == SGX_SUCCESS ) return 1;

	return 0;
}

int E_DRNG::rand64 (ULONG64 *rand)
{
	int retries= 10;

	while (retries--) if ( sgx_read_rand((unsigned char *) rand, 8) == SGX_SUCCESS ) return 1;

	return 0;
}

ULONG E_DRNG::get_n_rand32 (ULONG32 *buf, ULONG n, ULONG retries)
{
	while (retries--) if ( sgx_read_rand((unsigned char *) buf, n*4) == SGX_SUCCESS ) return n;

	return 0;
}

ULONG E_DRNG::get_n_rand64 (ULONG64 *buf, ULONG n, ULONG retries)
{
	while (retries--) if ( sgx_read_rand((unsigned char *) buf, n*8) == SGX_SUCCESS ) return n;

	return 0;
}


//-----------------------------------------------
// RDSEED internal methods
//-----------------------------------------------

int E_DRNG::seed32 (ULONG32 *seed)
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

int E_DRNG::seed64 (ULONG64 *seed)
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

ULONG E_DRNG::get_n_seed32 (ULONG32 *buf, ULONG n, ULONG retries)
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

ULONG E_DRNG::get_n_seed64 (ULONG64 *buf, ULONG n, ULONG retries)
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
		count= get_n_seed32((ULONG32 *)(buf)+count, n, retries);
		if ( count == n ) return n;
		return n/2 + int(count/2);
	}

	return int(count/2);
# endif
#else
	return seed_from_rdrand(buf, 8*n);
#endif
}

ULONG E_DRNG::seed_from_rdrand (void *buf, ULONG n)
{
	// Use CMAC to generate 128-bit seeds from RDRAND. This is expensive
	// but if we don't have RDSEED this is our only option.
	//
	// The DRNG is guaranteed to reseed after 512 128-bit samples have been generated.

	unsigned char key[16], rand[16*512];
	sgx_cmac_128bit_tag_t hash;
	unsigned char *bp= (unsigned char *) buf;
	ULONG count= 0;
	sgx_cmac_state_handle_t hcmac;

	// Create an ephemeral key

	if ( sgx_read_rand(key, 16) != SGX_SUCCESS ) {
		return 0;
	}

	// Set up CMAC

	if ( sgx_cmac128_init((const sgx_cmac_128bit_key_t *) key, &hcmac) != SGX_SUCCESS ) {
		return 0;
	}

	while (n) {
		ULONG chunk= ( n >= 16 ) ? 16 : n;

		// Fill our buffer with RDRAND values

		if ( sgx_read_rand(rand, 16*512) != SGX_SUCCESS ) {
			goto cleanup;
		}

		// Send our random values

		if ( sgx_cmac128_update(rand, 16*512, hcmac) != SGX_SUCCESS ) {
			// Error
			goto cleanup;
		}

		// The hash is our 128-bit seed value

		if ( sgx_cmac128_final(hcmac, &hash) != SGX_SUCCESS ) {
			// Error
			goto cleanup;
		}
		
		memcpy(bp, hash, chunk);
		count+= chunk;
		n-= chunk;
		bp+= chunk;
	}

cleanup:
	sgx_cmac128_close(hcmac);
	return count;
}

// Fast ceiling of log base 2
// http://stackoverflow.com/questions/3272424/compute-fast-log-base-2-ceiling
// Question asked by: kevinlawler (http://stackoverflow.com/users/365478/kevinlawler)
// Answered by: dgobbi (http://stackoverflow.com/users/2154690/dgobbi)
// Licensed under http://creativecommons.org/licenses/by-sa/3.0/
// Changes to variable names only. [-JM]

int E_DRNG::ceiling_log2 (ULONGLONG n)
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