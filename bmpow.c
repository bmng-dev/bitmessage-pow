
#include <Windows.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/sha.h>

#if defined(__GNUC__)
  #define EXPORT __attribute__ ((__visibility__("default")))
#elif defined(_WIN32)
  #define EXPORT __declspec(dllexport)
#endif

#define HASH_SIZE SHA512_DIGEST_LENGTH
#define POW_BUFFER_SIZE sizeof(uint64_t) + HASH_SIZE

typedef unsigned __int8 byte_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;

/* http://segfault.kiev.ua/~netch/articles/20131219-bswap.txt
 * https://blogs.oracle.com/DanX/entry/optimizing_byte_swapping_for_fun
 */
#define BSWAP_64(x) ( ((uint64_t)(x) << 56) | \
					 (((uint64_t)(x) << 40) & 0x00ff000000000000ULL) | \
					 (((uint64_t)(x) << 24) & 0x0000ff0000000000ULL) | \
					 (((uint64_t)(x) <<  8) & 0x000000ff00000000ULL) | \
					 (((uint64_t)(x) >>  8) & 0x00000000ff000000ULL) | \
					 (((uint64_t)(x) >> 24) & 0x0000000000ff0000ULL) | \
					 (((uint64_t)(x) >> 40) & 0x000000000000ff00ULL) | \
					  ((uint64_t)(x) >> 56) )

byte_t *max_val;
byte_t *initialHash;
uint64_t successval = 0;
uint32_t numthreads = 0;

DWORD WINAPI threadfunc(LPVOID param) {
	uint32_t incamt = *((uint32_t*)param);
	SHA512_CTX sha;
	byte_t buf[POW_BUFFER_SIZE];
	byte_t output[HASH_SIZE];

	uint64_t * nonce = (uint64_t *)buf;

	(*nonce) = incamt;
	memcpy(buf + sizeof(uint64_t), initialHash, HASH_SIZE);

	do {
		SHA512_Init(&sha);
		SHA512_Update(&sha, buf, POW_BUFFER_SIZE);
		SHA512_Final(output, &sha);
		SHA512_Init(&sha);
		SHA512_Update(&sha, output, HASH_SIZE);
		SHA512_Final(output, &sha);

		if (0 >= memcmp(output, max_val, sizeof(uint64_t))) {
			successval = BSWAP_64(*nonce);
			break;
		}
	} while(((*nonce) += numthreads) > numthreads);
	return EXIT_SUCCESS;
}

void getnumthreads()
{
	DWORD_PTR dwProcessAffinity, dwSystemAffinity;
	size_t len = sizeof(dwProcessAffinity);
	int i;
	if (numthreads > 0)
		return;
	GetProcessAffinityMask(GetCurrentProcess(), &dwProcessAffinity, &dwSystemAffinity);
	for (i = 0; i < len * 8; i++)
		if (dwProcessAffinity & (1LL << i))
			numthreads++;
	if (numthreads == 0) // something failed
		numthreads = 1;
}

EXPORT uint64_t BitmessagePOW(byte_t * starthash, uint64_t target)
{
	HANDLE* threads;
	uint32_t *threaddata;
	int i;
	successval = 0;
	target = BSWAP_64(target);
	max_val = (byte_t *)&target;
	getnumthreads();
	initialHash = (byte_t *)starthash;
	threads = (HANDLE*)calloc(sizeof(HANDLE), numthreads);
	threaddata = (uint32_t *)calloc(sizeof(uint32_t), numthreads);
	for (i = 0; i < numthreads; i++) {
		threaddata[i] = (uint32_t)i;
		threads[i] = CreateThread(NULL, 0, threadfunc, (LPVOID)&threaddata[i], 0, NULL);
		SetThreadPriority(threads[i], THREAD_PRIORITY_IDLE);
	}
	WaitForMultipleObjects(numthreads, threads, TRUE, INFINITE);
	free(threads);
	free(threaddata);
	return successval;
}
