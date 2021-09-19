#pragma once

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

#define MD5ROUNDEND(a, b, c, d, f, s)\
	((a) = (d));\
	((d) = (c));\
	((c) = (b));\
	((b) = (b) + ROL32((f), (s)))
#define MD5ROUND0(a, b, c, d, f, k, m, s)\
	((f) = ((d) ^ ((b) & ((c) ^ (d)))) + (a) + (k) + (m));\
	MD5ROUNDEND((a), (b), (c), (d), (f), (s))

#define MD5ROUND1(a, b, c, d, f, k, m, s)\
	((f) = ((c) ^ ((d) & ((b) ^ (c)))) + (a) + (k) + (m));\
	MD5ROUNDEND((a), (b), (c), (d), (f), (s))

#define MD5ROUND2(a, b, c, d, f, k, m, s)\
	((f) = ((b) ^ (c) ^ (d)) + (a) + (k) + (m));\
	MD5ROUNDEND((a), (b), (c), (d), (f), (s))

#define MD5ROUND3(a, b, c, d, f, k, m, s)\
	((f) = ((c) ^ ((b) | (~d))) + (a) + (k) + (m));\
	MD5ROUNDEND((a), (b), (c), (d), (f), (s))

unsigned char* md5Hash(unsigned char* message, uint64_t length, unsigned char* digest)
{
	// Magic initialization constants
	unsigned int magic[4] = {
		0x67452301, 0xefcdab89,
		0x98badcfe, 0x10325476
	};

	// Pre-processing //
	unsigned int paddedLength = (((length + 8) >> 6) + 1) << 6; // Reserve 8 bytes so that length can be stored. Always a multiple of 64
	unsigned char* paddedMesssage;
	paddedMesssage = (unsigned char*)calloc(paddedLength, 1);
	memcpy(paddedMesssage, message, length);
	paddedMesssage[length] = 0x80; // Append 1 bit to the end of the message
	uint64_t lengthInBits = length * 8;
	memmove(paddedMesssage + paddedLength - 8, &lengthInBits, 8);

	// For each 64 byte chunk //
	for (int chunk = 0; chunk < paddedLength >> 6; chunk++)
	{
		const unsigned int M[16]; // Split padded message in to 16 integers
		memmove(M, paddedMesssage + (chunk << 6), 64);
		
		unsigned int F = 3614090359 + M[0]; // Slightly precalculate the first value
		unsigned int A = magic[3];
		unsigned int D = magic[2];
		unsigned int C = magic[1];
		unsigned int B = magic[1] + ROL32(F, 7);

		/* // Calculate K constants //
		unsigned int K[64];
		for (int i = 0; i < 64; i++)
			K[i] = floor(4294967296.0 * fabs(sin(i + 1)));
		*/

		MD5ROUND0(A, B, C, D, F, 0xe8c7b756, M[1], 12);
		MD5ROUND0(A, B, C, D, F, 0x242070db, M[2], 17);
		MD5ROUND0(A, B, C, D, F, 0xc1bdceee, M[3], 22);
		MD5ROUND0(A, B, C, D, F, 0xf57c0faf, M[4], 7);
		MD5ROUND0(A, B, C, D, F, 0x4787c62a, M[5], 12);
		MD5ROUND0(A, B, C, D, F, 0xa8304613, M[6], 17);
		MD5ROUND0(A, B, C, D, F, 0xfd469501, M[7], 22);
		MD5ROUND0(A, B, C, D, F, 0x698098d8, M[8], 7);
		MD5ROUND0(A, B, C, D, F, 0x8b44f7af, M[9], 12);
		MD5ROUND0(A, B, C, D, F, 0xffff5bb1, M[10], 17);
		MD5ROUND0(A, B, C, D, F, 0x895cd7be, M[11], 22);
		MD5ROUND0(A, B, C, D, F, 0x6b901122, M[12], 7);
		MD5ROUND0(A, B, C, D, F, 0xfd987193, M[13], 12);
		MD5ROUND0(A, B, C, D, F, 0xa679438e, M[14], 17);
		MD5ROUND0(A, B, C, D, F, 0x49b40821, M[15], 22);
		MD5ROUND1(A, B, C, D, F, 0xf61e2562, M[1], 5);
		MD5ROUND1(A, B, C, D, F, 0xc040b340, M[6], 9);
		MD5ROUND1(A, B, C, D, F, 0x265e5a51, M[11], 14);
		MD5ROUND1(A, B, C, D, F, 0xe9b6c7aa, M[0], 20);
		MD5ROUND1(A, B, C, D, F, 0xd62f105d, M[5], 5);
		MD5ROUND1(A, B, C, D, F, 0x02441453, M[10], 9);
		MD5ROUND1(A, B, C, D, F, 0xd8a1e681, M[15], 14);
		MD5ROUND1(A, B, C, D, F, 0xe7d3fbc8, M[4], 20);
		MD5ROUND1(A, B, C, D, F, 0x21e1cde6, M[9], 5);
		MD5ROUND1(A, B, C, D, F, 0xc33707d6, M[14], 9);
		MD5ROUND1(A, B, C, D, F, 0xf4d50d87, M[3], 14);
		MD5ROUND1(A, B, C, D, F, 0x455a14ed, M[8], 20);
		MD5ROUND1(A, B, C, D, F, 0xa9e3e905, M[13], 5);
		MD5ROUND1(A, B, C, D, F, 0xfcefa3f8, M[2], 9);
		MD5ROUND1(A, B, C, D, F, 0x676f02d9, M[7], 14);
		MD5ROUND1(A, B, C, D, F, 0x8d2a4c8a, M[12], 20);
		MD5ROUND2(A, B, C, D, F, 0xfffa3942, M[5], 4);
		MD5ROUND2(A, B, C, D, F, 0x8771f681, M[8], 11);
		MD5ROUND2(A, B, C, D, F, 0x6d9d6122, M[11], 16);
		MD5ROUND2(A, B, C, D, F, 0xfde5380c, M[14], 23);
		MD5ROUND2(A, B, C, D, F, 0xa4beea44, M[1], 4);
		MD5ROUND2(A, B, C, D, F, 0x4bdecfa9, M[4], 11);
		MD5ROUND2(A, B, C, D, F, 0xf6bb4b60, M[7], 16);
		MD5ROUND2(A, B, C, D, F, 0xbebfbc70, M[10], 23);
		MD5ROUND2(A, B, C, D, F, 0x289b7ec6, M[13], 4);
		MD5ROUND2(A, B, C, D, F, 0xeaa127fa, M[0], 11);
		MD5ROUND2(A, B, C, D, F, 0xd4ef3085, M[3], 16);
		MD5ROUND2(A, B, C, D, F, 0x04881d05, M[6], 23);
		MD5ROUND2(A, B, C, D, F, 0xd9d4d039, M[9], 4);
		MD5ROUND2(A, B, C, D, F, 0xe6db99e5, M[12], 11);
		MD5ROUND2(A, B, C, D, F, 0x1fa27cf8, M[15], 16);
		MD5ROUND2(A, B, C, D, F, 0xc4ac5665, M[2], 23);
		MD5ROUND3(A, B, C, D, F, 0xf4292244, M[0], 6);
		MD5ROUND3(A, B, C, D, F, 0x432aff97, M[7], 10);
		MD5ROUND3(A, B, C, D, F, 0xab9423a7, M[14], 15);
		MD5ROUND3(A, B, C, D, F, 0xfc93a039, M[5], 21);
		MD5ROUND3(A, B, C, D, F, 0x655b59c3, M[12], 6);
		MD5ROUND3(A, B, C, D, F, 0x8f0ccc92, M[3], 10);
		MD5ROUND3(A, B, C, D, F, 0xffeff47d, M[10], 15);
		MD5ROUND3(A, B, C, D, F, 0x85845dd1, M[1], 21);
		MD5ROUND3(A, B, C, D, F, 0x6fa87e4f, M[8], 6);
		MD5ROUND3(A, B, C, D, F, 0xfe2ce6e0, M[15], 10);
		MD5ROUND3(A, B, C, D, F, 0xa3014314, M[6], 15);
		MD5ROUND3(A, B, C, D, F, 0x4e0811a1, M[13], 21);
		MD5ROUND3(A, B, C, D, F, 0xf7537e82, M[4], 6);
		MD5ROUND3(A, B, C, D, F, 0xbd3af235, M[11], 10);
		MD5ROUND3(A, B, C, D, F, 0x2ad7d2bb, M[2], 15);
		MD5ROUND3(A, B, C, D, F, 0xeb86d391, M[9], 21);
		
		magic[0] = magic[0] + A;
		magic[1] = magic[1] + B;
		magic[2] = magic[2] + C;
		magic[3] = magic[3] + D;
	}
	free(paddedMesssage);
	memmove(digest, magic, 16);
	return digest;
}