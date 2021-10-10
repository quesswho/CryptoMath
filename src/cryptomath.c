#include "cryptomath.h"
#include <stdio.h>

void md5_message(const char* message, const size_t length, uint8_t digest[16])
{
	union Message {
		uint8_t* msg8;
		uint32_t* msg32;	
		uint64_t* msg64;
	} unionMessage, signatureBlock;

	const uint32_t signatureBlockLength = ((length & 0x3F) + 72) & (~0x3F); // ((length % 64) + 64 + 8) & (~0x3F). x & (~0x3F) will truncate last bits so that it's a multiple of 64
	signatureBlock.msg8 = (uint8_t*)calloc(signatureBlockLength, 1);
	memcpy(signatureBlock.msg8, message + (length & (~0x3F)), length & 0x3F);
	signatureBlock.msg8[length & 0x3F] = 0x80; // Append 1 bit to the end of the message
	signatureBlock.msg64[((signatureBlockLength - 8) >> 3)] = length << 3; // set last 8 bytes to the message length in bits

	unionMessage.msg8 = (uint8_t*)message; // Assign to a union so that it can be represented as uint32_t

	// Magic initialization constants
	unsigned int magic[4] = {
		0x67452301, 0xefcdab89,
		0x98badcfe, 0x10325476
	};

	// For each 64 byte multiple of message //
	for (int block = 0; block < ((length >> 2) & ~0xF); block+=16)
		md5_block(unionMessage.msg32 + block, magic);

	// For each 64 byte signature block //
	for (int block = 0; block < ((signatureBlockLength >> 2) & ~0xF); block+=16)
		md5_block(signatureBlock.msg32 + block, magic);
   
	free(signatureBlock.msg8);
	memmove(digest, magic, 16);
}

void md5_block(const uint32_t block[16], uint32_t digest[4])
{
	// MD5 Macros
	#define MD5_FUNCEND(a, b, f, k, m, s) \
		((a) = (f) + (a) + (k) + (m)); /* Evaluate f and assign to a */ \
		((a) = (b) + ROL32((a), (s)));

	#define MD5_FUNCF(a, b, c, d, k, m, s) \
		MD5_FUNCEND((a), (b), MD5_F((b), (c), (d)), (k), (m), (s))
	#define MD5_FUNCG(a, b, c, d, k, m, s) \
		MD5_FUNCEND((a), (b), MD5_G((b), (c), (d)), (k), (m), (s))
	
	#define MD5_FUNCH(a, b, c, d, k, m, s) \
		MD5_FUNCEND((a), (b), MD5_H((b), (c), (d)), (k), (m), (s))
	#define MD5_FUNCI(a, b, c, d, k, m, s) \
		MD5_FUNCEND((a), (b), MD5_I((b), (c), (d)), (k), (m), (s))

    #define MD5_F(b, c, d) ((d) ^ ((b) & ((c) ^ (d))))
	#define MD5_G(b, c, d) (((d) & (b)) + (~(d) & (c)))
	#define MD5_H(b, c, d) ((b) ^ (c) ^ (d))
	#define MD5_I(b, c, d) ((c) ^ ((b) | (~d)))

	// These will be optimized after inlining
	uint32_t A = digest[0];
	uint32_t B = digest[1];
	uint32_t C = digest[2];
	uint32_t D = digest[3];

	/* // Calculate K constants //
	uint32_t K[64];
	for (int i = 0; i < 64; i++)
		K[i] = floor(4294967296.0 * fabs(sin(i + 1)));
	*/

	MD5_FUNCF(A, B, C, D, 0xd76aa478, block[0], 7);
	MD5_FUNCF(D, A, B, C, 0xe8c7b756, block[1], 12);
	MD5_FUNCF(C, D, A, B, 0x242070db, block[2], 17);
	MD5_FUNCF(B, C, D, A, 0xc1bdceee, block[3], 22);
	MD5_FUNCF(A, B, C, D, 0xf57c0faf, block[4], 7);
	MD5_FUNCF(D, A, B, C, 0x4787c62a, block[5], 12);
	MD5_FUNCF(C, D, A, B, 0xa8304613, block[6], 17);
	MD5_FUNCF(B, C, D, A, 0xfd469501, block[7], 22);
	MD5_FUNCF(A, B, C, D, 0x698098d8, block[8], 7);
	MD5_FUNCF(D, A, B, C, 0x8b44f7af, block[9], 12);
	MD5_FUNCF(C, D, A, B, 0xffff5bb1, block[10], 17);
	MD5_FUNCF(B, C, D, A, 0x895cd7be, block[11], 22);
	MD5_FUNCF(A, B, C, D, 0x6b901122, block[12], 7);
	MD5_FUNCF(D, A, B, C, 0xfd987193, block[13], 12);
	MD5_FUNCF(C, D, A, B, 0xa679438e, block[14], 17);
	MD5_FUNCF(B, C, D, A, 0x49b40821, block[15], 22);

	MD5_FUNCG(A, B, C, D, 0xf61e2562, block[1], 5);
	MD5_FUNCG(D, A, B, C, 0xc040b340, block[6], 9);
	MD5_FUNCG(C, D, A, B, 0x265e5a51, block[11], 14);
	MD5_FUNCG(B, C, D, A, 0xe9b6c7aa, block[0], 20);
	MD5_FUNCG(A, B, C, D, 0xd62f105d, block[5], 5);
	MD5_FUNCG(D, A, B, C, 0x02441453, block[10], 9);
	MD5_FUNCG(C, D, A, B, 0xd8a1e681, block[15], 14);
	MD5_FUNCG(B, C, D, A, 0xe7d3fbc8, block[4], 20);
	MD5_FUNCG(A, B, C, D, 0x21e1cde6, block[9], 5);
	MD5_FUNCG(D, A, B, C, 0xc33707d6, block[14], 9);
	MD5_FUNCG(C, D, A, B, 0xf4d50d87, block[3], 14);
	MD5_FUNCG(B, C, D, A, 0x455a14ed, block[8], 20);
	MD5_FUNCG(A, B, C, D, 0xa9e3e905, block[13], 5);
	MD5_FUNCG(D, A, B, C, 0xfcefa3f8, block[2], 9);
	MD5_FUNCG(C, D, A, B, 0x676f02d9, block[7], 14);
	MD5_FUNCG(B, C, D, A, 0x8d2a4c8a, block[12], 20);

	MD5_FUNCH(A, B, C, D, 0xfffa3942, block[5], 4);
	MD5_FUNCH(D, A, B, C, 0x8771f681, block[8], 11);
	MD5_FUNCH(C, D, A, B, 0x6d9d6122, block[11], 16);
	MD5_FUNCH(B, C, D, A, 0xfde5380c, block[14], 23);
	MD5_FUNCH(A, B, C, D, 0xa4beea44, block[1], 4);
	MD5_FUNCH(D, A, B, C, 0x4bdecfa9, block[4], 11);
	MD5_FUNCH(C, D, A, B, 0xf6bb4b60, block[7], 16);
	MD5_FUNCH(B, C, D, A, 0xbebfbc70, block[10], 23);
	MD5_FUNCH(A, B, C, D, 0x289b7ec6, block[13], 4);
	MD5_FUNCH(D, A, B, C, 0xeaa127fa, block[0], 11);
	MD5_FUNCH(C, D, A, B, 0xd4ef3085, block[3], 16);
	MD5_FUNCH(B, C, D, A, 0x04881d05, block[6], 23);
	MD5_FUNCH(A, B, C, D, 0xd9d4d039, block[9], 4);
	MD5_FUNCH(D, A, B, C, 0xe6db99e5, block[12], 11);
	MD5_FUNCH(C, D, A, B, 0x1fa27cf8, block[15], 16);
	MD5_FUNCH(B, C, D, A, 0xc4ac5665, block[2], 23);

	MD5_FUNCI(A, B, C, D, 0xf4292244, block[0], 6);
	MD5_FUNCI(D, A, B, C, 0x432aff97, block[7], 10);
	MD5_FUNCI(C, D, A, B, 0xab9423a7, block[14], 15);
	MD5_FUNCI(B, C, D, A, 0xfc93a039, block[5], 21);
	MD5_FUNCI(A, B, C, D, 0x655b59c3, block[12], 6);
	MD5_FUNCI(D, A, B, C, 0x8f0ccc92, block[3], 10);
	MD5_FUNCI(C, D, A, B, 0xffeff47d, block[10], 15);
	MD5_FUNCI(B, C, D, A, 0x85845dd1, block[1], 21);
	MD5_FUNCI(A, B, C, D, 0x6fa87e4f, block[8], 6);
	MD5_FUNCI(D, A, B, C, 0xfe2ce6e0, block[15], 10);
	MD5_FUNCI(C, D, A, B, 0xa3014314, block[6], 15);
	MD5_FUNCI(B, C, D, A, 0x4e0811a1, block[13], 21);
	MD5_FUNCI(A, B, C, D, 0xf7537e82, block[4], 6);
	MD5_FUNCI(D, A, B, C, 0xbd3af235, block[11], 10);
	MD5_FUNCI(C, D, A, B, 0x2ad7d2bb, block[2], 15);
	MD5_FUNCI(B, C, D, A, 0xeb86d391, block[9], 21);

	digest[0] = digest[0] + A;
	digest[1] = digest[1] + B;
	digest[2] = digest[2] + C;
	digest[3] = digest[3] + D;
}

void sha1_message(const char* message, const size_t length, uint8_t digest[20])
{
	// Pre-processing //
	unsigned int paddedLength = (((length + 8) >> 6) + 1) << 6; // Reserve 8 bytes so that length can be stored. Always a multiple of 64
	unsigned char* paddedMesssage;
	paddedMesssage = (unsigned char*)calloc(paddedLength, 1);
	memcpy(paddedMesssage, message, length);
	paddedMesssage[length] = 0x80; // Append 1 bit to the end of the message
	uint64_t lengthInBits = length * 8;
	memmove(paddedMesssage + paddedLength - 8, &lengthInBits, 8);
}
