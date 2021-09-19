#pragma once

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

unsigned char* md5Hash(unsigned char* message, uint64_t length, unsigned char* digest) 
{
	// Round shift constants
	const unsigned int s[64] = {
		7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
		5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
		4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
		6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
	};

	/*
	unsigned int K[64];
	for (int i = 0; i < 64; i++)
		K[i] = floor(4294967296.0 * fabs(sin(i + 1)));
	*/

	// Precomputed constants from above
	const unsigned int K[64] = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	};
	
	// Magic initialization constants
	unsigned int a0 = 0x67452301;
	unsigned int b0 = 0xefcdab89;
	unsigned int c0 = 0x98badcfe;
	unsigned int d0 = 0x10325476;

	// Pre-processing //
	unsigned int paddedLength = (((length + 8) >> 6) + 1) << 6; // Reserve 8 bytes so that length can be stored
	unsigned char* paddedMesssage;
	paddedMesssage = (unsigned char*)calloc(paddedLength, 1);
	memcpy(paddedMesssage, message, length);
	paddedMesssage[length] = 0x80; // Append 1 bit to the end of the message
	uint64_t lengthInBits = length * 8;
	memcpy(paddedMesssage + paddedLength - 8, &lengthInBits, 8);
	

	// Main loop //
	for (int chunk = 0; chunk < paddedLength >> 6; chunk++)
	{
		const unsigned int M[16]; // Divide padded message in to 16 integers
		for (int i = 0; i < 16; i++)
		{
			memcpy(M + i, paddedMesssage + i * 4 + chunk * 64, 4);
		}
		unsigned int A = a0;
		unsigned int B = b0;
		unsigned int C = c0;
		unsigned int D = d0;

		unsigned int F, g;
		for (int i = 0; i < 64; i++)
		{
			if (i < 16)
			{
				F = D ^ (B & (C ^ D)); // (B & C) | ((~B) & D)
 				g = i;
			}
			else if (i < 32)
			{
				F = C ^ (D & (B ^ C)); // (D & B) | ((~D) & C)
				g = (5 * i + 1) & 0xF; // & 0xF equilivalent to mod 16
			}
			else if (i < 48)
			{
				F = B ^ C ^ D;
				g = (3 * i + 5) & 0xF;
			}
			else
			{
				F = C ^ (B | (~D));
				g = (7 * i) & 0xF;
			}
			F = F + A + K[i] + M[g];
			A = D;
			D = C;
			C = B;
			B = B + ROL32(F, s[i]);
		}
		a0 = a0 + A;
		b0 = b0 + B;
		c0 = c0 + C;
		d0 = d0 + D;
	}
	free(paddedMesssage);
	memcpy(digest, &a0, 4);
	memcpy(digest + 4, &b0, 4);
	memcpy(digest + 8, &c0, 4);
	memcpy(digest + 12, &d0, 4);
		
	return digest;
}