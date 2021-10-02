#include <stdio.h>
#include <time.h>

#include "cryptomath.h"

#define MEASURE_SPEED 1

int main()
{
	const char str[] = "The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog";
	unsigned char hash[16];

#if MEASURE_SPEED
	const int iterations = 10000000;
	int len = strlen(str);
	clock_t start = clock();
	for(int i = 0; i < iterations; i++)
		md5_message(str, len, hash);
	printf("%.2fMH/s\n", (double)iterations / ((double)(clock() - start) / CLOCKS_PER_SEC * 1000000));
#endif
	md5_message(str, strlen(str), hash);
	for (int i = 0; i < 16; i++)
		printf("%02x", (unsigned int)(unsigned char)hash[i]);

	printf("\n");
	return 0;
}
