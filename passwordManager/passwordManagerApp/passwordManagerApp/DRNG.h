#pragma once

#include <Windows.h>

class DRNG;

typedef class DRNG DRNG;

class DRNG
{
	int rand32 (ULONG32 *rand);
	int rand64 (ULONG64 *rand);
	ULONG get_n_rand32 (ULONG32 *buf, ULONG n, ULONG retries);
	ULONG get_n_rand64 (ULONG64 *buf, ULONG n, ULONG retries);

	int seed32 (ULONG32 *seed);
	int seed64 (ULONG64 *seed);
	ULONG get_n_seed32 (ULONG32 *buf, ULONG n, ULONG retries);
	ULONG get_n_seed64 (ULONG64 *buf, ULONG n, ULONG retries);

	ULONG seed_from_rdrand (void *buf, ULONG n);

	int DRNG::ceiling_log2 (ULONGLONG n);

public:
	DRNG(void);
	DRNG(int *info);
	~DRNG(void);

	int have_rdrand(void);
	int have_rdseed(void);

	// General purpose random numbers 0 <= r < max

	int random (ULONGLONG max, ULONGLONG *rand);

	// Random seeds, suitable for static encryption keys and seeding
	// other PRNGs.

	ULONG get_seed_bytes (void *buf, ULONG n);
	ULONG get_rand_bytes (void *buf, ULONG n);
};

