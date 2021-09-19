#include <stdio.h>
#include <time.h>

#include "CryptoMath.h"

int main()
{
	const unsigned char* str = "The quick brown fox jumps over the lazy dog";
	const unsigned char hash[16];

	md5Hash(str, strlen(str), &hash);
	for (int i = 0; i < 16; i++)
		printf("%02x", (unsigned int)(unsigned char)hash[i]);

	return 0;
}
