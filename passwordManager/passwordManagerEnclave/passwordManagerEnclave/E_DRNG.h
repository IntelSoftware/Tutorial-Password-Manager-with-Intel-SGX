#pragma once

#include <sgx.h>

class E_DRNG;
typedef class E_DRNG E_DRNG;

class E_DRNG
{
	int rand32 (uint32_t *rand);
	int rand64 (uint64_t *rand);
	unsigned long get_n_rand32 (uint32_t *buf, unsigned long n, unsigned long retries);
	unsigned long get_n_rand64 (uint64_t *buf, unsigned long n, unsigned long retries);

	int seed32 (uint32_t *seed);
	int seed64 (uint64_t *seed);
	unsigned long get_n_seed32 (uint32_t *buf, unsigned long n, unsigned long retries);
	unsigned long get_n_seed64 (uint64_t *buf, unsigned long n, unsigned long retries);

	unsigned long seed_from_rdrand (void *buf, unsigned long n);

	int ceiling_log2 (unsigned long long n);

public:
	E_DRNG(void);
	E_DRNG(int *info);
	~E_DRNG(void);

	int have_rdseed(void);

	// General purpose random numbers 0 <= r < max

	int random (unsigned long long max, unsigned long long *rand);

	// Random seeds, suitable for static encryption keys and seeding
	// other PRNGs.

	unsigned long get_seed_bytes (void *buf, unsigned long n);
	unsigned long get_rand_bytes (void *buf, unsigned long n);
};

