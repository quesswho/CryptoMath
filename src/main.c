#include <stdio.h>
#include <time.h>

#include "cryptomath.h"

#define MEASURE_SPEED 1

int main()
{
	const char str[] = "The quick brown fox jumps over the lazy dog";
	unsigned char hash[16];

#if MEASURE_SPEED
	const int iterations = 10000000;
	int len = strlen(str);
	//clock_t start = clock();
	clock_t start = clock();
	for(int i = 0; i < iterations; i++)
		md5Hash(str, len, hash);
	printf("%.1fKH/s", (double)iterations / (clock() - start) * CLOCKS_PER_SEC / 1000);
#else
	md5Hash(str, strlen(str), hash);
	for (int i = 0; i < 16; i++)
		printf("%02x", (unsigned int)(unsigned char)hash[i]);

#endif

	printf("\n");
	return 0;
}
