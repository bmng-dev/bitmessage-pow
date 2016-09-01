
#include "Winsock.h"
#include "Windows.h"
#define uint64_t unsigned __int64

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "openssl/sha.h"

#define HASH_SIZE 64
#define BUFLEN 16384

#if defined(__GNUC__)
  #define EXPORT __attribute__ ((__visibility__("default")))
#elif defined(_WIN32)
  #define EXPORT __declspec(dllexport)
#endif

#define ntohll(x) ( ( (uint64_t)(ntohl( (unsigned int)((x << 32) >> 32) )) << 32) | ntohl( ((unsigned int)(x >> 32)) ) )

unsigned long long max_val;
unsigned char *initialHash;
unsigned long long successval = 0;
unsigned int numthreads = 0;

DWORD WINAPI threadfunc(LPVOID param) {
	unsigned int incamt = *((unsigned int*)param);
	SHA512_CTX sha;
	unsigned char buf[HASH_SIZE + sizeof(uint64_t)];
	unsigned char output[HASH_SIZE];

	memcpy(buf + sizeof(uint64_t), initialHash, HASH_SIZE);

	unsigned long long tmpnonce = (unsigned long long)incamt;
	unsigned long long * nonce = (unsigned long long *)buf;
	unsigned long long * hash = (unsigned long long *)output;
	while (successval == 0) {
		tmpnonce += numthreads;

		(*nonce) = ntohll(tmpnonce); /* increment nonce */
		SHA512_Init(&sha);
		SHA512_Update(&sha, buf, HASH_SIZE + sizeof(uint64_t));
		SHA512_Final(output, &sha);
		SHA512_Init(&sha);
		SHA512_Update(&sha, output, HASH_SIZE);
		SHA512_Final(output, &sha);

		if (ntohll(*hash) < max_val) {
			successval = tmpnonce;
		}
	}
	return EXIT_SUCCESS;
}

void getnumthreads()
{
	DWORD_PTR dwProcessAffinity, dwSystemAffinity;
	size_t len = sizeof(dwProcessAffinity);
	if (numthreads > 0)
		return;
	GetProcessAffinityMask(GetCurrentProcess(), &dwProcessAffinity, &dwSystemAffinity);
	for (unsigned int i = 0; i < len * 8; i++)
		if (dwProcessAffinity & (1LL << i))
			numthreads++;
	if (numthreads == 0) // something failed
		numthreads = 1;
	printf("Number of threads: %i\n", (int)numthreads);
}

EXPORT unsigned long long BitmessagePOW(unsigned char * starthash, unsigned long long target)
{
	successval = 0;
	max_val = target;
	getnumthreads();
	initialHash = (unsigned char *)starthash;
	HANDLE* threads = (HANDLE*)calloc(sizeof(HANDLE), numthreads);
	unsigned int *threaddata = (unsigned int *)calloc(sizeof(unsigned int), numthreads);
	for (unsigned int i = 0; i < numthreads; i++) {
		threaddata[i] = i;
		threads[i] = CreateThread(NULL, 0, threadfunc, (LPVOID)&threaddata[i], 0, NULL);
		SetThreadPriority(threads[i], THREAD_PRIORITY_IDLE);
	}
	WaitForMultipleObjects(numthreads, threads, TRUE, INFINITE);
	free(threads);
	free(threaddata);
	return successval;
}
