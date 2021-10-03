#include "cryptomath.h"

void md5_message(const char* message, const uint64_t length, uint8_t digest[16])
{
	// Calculation Macros
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

	// Pre-processing //
	unsigned int paddedLength = (((length + 8) >> 6) + 1) << 6; // Reserve 8 bytes so that length can be stored. Always a multiple of 64
	unsigned char* paddedMessage;
	paddedMessage = (unsigned char*)calloc(paddedLength, 1);
	memcpy(paddedMessage, message, length);
	paddedMessage[length] = 0x80; // Append 1 bit to the end of the message
	uint64_t lengthInBits = length * 8;
	memmove(paddedMessage + paddedLength - 8, &lengthInBits, 8);

	// Magic initialization constants
	unsigned int magic[4] = {
		0x67452301, 0xefcdab89,
		0x98badcfe, 0x10325476
	};

	// For each 64 byte chunk //
	for (int chunk = 0; chunk < paddedLength >> 6; chunk++)
	{
		unsigned int M[16]; // Split padded message in to 16 integers
        memmove(M, paddedMessage + (chunk << 6), 64);

		unsigned int A = magic[0];
		unsigned int B = magic[1];
		unsigned int C = magic[2];
		unsigned int D = magic[3];

		/* // Calculate K constants //
		unsigned int K[64];
		for (int i = 0; i < 64; i++)
			K[i] = floor(4294967296.0 * fabs(sin(i + 1)));
		*/

		MD5_FUNCF(A, B, C, D, 0xd76aa478, M[0], 7);
		MD5_FUNCF(D, A, B, C, 0xe8c7b756, M[1], 12);
		MD5_FUNCF(C, D, A, B, 0x242070db, M[2], 17);
		MD5_FUNCF(B, C, D, A, 0xc1bdceee, M[3], 22);
		MD5_FUNCF(A, B, C, D, 0xf57c0faf, M[4], 7);
		MD5_FUNCF(D, A, B, C, 0x4787c62a, M[5], 12);
		MD5_FUNCF(C, D, A, B, 0xa8304613, M[6], 17);
		MD5_FUNCF(B, C, D, A, 0xfd469501, M[7], 22);
		MD5_FUNCF(A, B, C, D, 0x698098d8, M[8], 7);
		MD5_FUNCF(D, A, B, C, 0x8b44f7af, M[9], 12);
		MD5_FUNCF(C, D, A, B, 0xffff5bb1, M[10], 17);
		MD5_FUNCF(B, C, D, A, 0x895cd7be, M[11], 22);
		MD5_FUNCF(A, B, C, D, 0x6b901122, M[12], 7);
		MD5_FUNCF(D, A, B, C, 0xfd987193, M[13], 12);
		MD5_FUNCF(C, D, A, B, 0xa679438e, M[14], 17);
		MD5_FUNCF(B, C, D, A, 0x49b40821, M[15], 22);

		MD5_FUNCG(A, B, C, D, 0xf61e2562, M[1], 5);
		MD5_FUNCG(D, A, B, C, 0xc040b340, M[6], 9);
		MD5_FUNCG(C, D, A, B, 0x265e5a51, M[11], 14);
		MD5_FUNCG(B, C, D, A, 0xe9b6c7aa, M[0], 20);
		MD5_FUNCG(A, B, C, D, 0xd62f105d, M[5], 5);
		MD5_FUNCG(D, A, B, C, 0x02441453, M[10], 9);
		MD5_FUNCG(C, D, A, B, 0xd8a1e681, M[15], 14);
		MD5_FUNCG(B, C, D, A, 0xe7d3fbc8, M[4], 20);
		MD5_FUNCG(A, B, C, D, 0x21e1cde6, M[9], 5);
		MD5_FUNCG(D, A, B, C, 0xc33707d6, M[14], 9);
		MD5_FUNCG(C, D, A, B, 0xf4d50d87, M[3], 14);
		MD5_FUNCG(B, C, D, A, 0x455a14ed, M[8], 20);
		MD5_FUNCG(A, B, C, D, 0xa9e3e905, M[13], 5);
		MD5_FUNCG(D, A, B, C, 0xfcefa3f8, M[2], 9);
		MD5_FUNCG(C, D, A, B, 0x676f02d9, M[7], 14);
		MD5_FUNCG(B, C, D, A, 0x8d2a4c8a, M[12], 20);
		
		MD5_FUNCH(A, B, C, D, 0xfffa3942, M[5], 4);
		MD5_FUNCH(D, A, B, C, 0x8771f681, M[8], 11);
		MD5_FUNCH(C, D, A, B, 0x6d9d6122, M[11], 16);
		MD5_FUNCH(B, C, D, A, 0xfde5380c, M[14], 23);
		MD5_FUNCH(A, B, C, D, 0xa4beea44, M[1], 4);
		MD5_FUNCH(D, A, B, C, 0x4bdecfa9, M[4], 11);
		MD5_FUNCH(C, D, A, B, 0xf6bb4b60, M[7], 16);
		MD5_FUNCH(B, C, D, A, 0xbebfbc70, M[10], 23);
		MD5_FUNCH(A, B, C, D, 0x289b7ec6, M[13], 4);
		MD5_FUNCH(D, A, B, C, 0xeaa127fa, M[0], 11);
		MD5_FUNCH(C, D, A, B, 0xd4ef3085, M[3], 16);
		MD5_FUNCH(B, C, D, A, 0x04881d05, M[6], 23);
		MD5_FUNCH(A, B, C, D, 0xd9d4d039, M[9], 4);
		MD5_FUNCH(D, A, B, C, 0xe6db99e5, M[12], 11);
		MD5_FUNCH(C, D, A, B, 0x1fa27cf8, M[15], 16);
		MD5_FUNCH(B, C, D, A, 0xc4ac5665, M[2], 23);

		MD5_FUNCI(A, B, C, D, 0xf4292244, M[0], 6);
		MD5_FUNCI(D, A, B, C, 0x432aff97, M[7], 10);
		MD5_FUNCI(C, D, A, B, 0xab9423a7, M[14], 15);
		MD5_FUNCI(B, C, D, A, 0xfc93a039, M[5], 21);
		MD5_FUNCI(A, B, C, D, 0x655b59c3, M[12], 6);
		MD5_FUNCI(D, A, B, C, 0x8f0ccc92, M[3], 10);
		MD5_FUNCI(C, D, A, B, 0xffeff47d, M[10], 15);
		MD5_FUNCI(B, C, D, A, 0x85845dd1, M[1], 21);
		MD5_FUNCI(A, B, C, D, 0x6fa87e4f, M[8], 6);
		MD5_FUNCI(D, A, B, C, 0xfe2ce6e0, M[15], 10);
		MD5_FUNCI(C, D, A, B, 0xa3014314, M[6], 15);
		MD5_FUNCI(B, C, D, A, 0x4e0811a1, M[13], 21);
		MD5_FUNCI(A, B, C, D, 0xf7537e82, M[4], 6);
		MD5_FUNCI(D, A, B, C, 0xbd3af235, M[11], 10);
		MD5_FUNCI(C, D, A, B, 0x2ad7d2bb, M[2], 15);
		MD5_FUNCI(B, C, D, A, 0xeb86d391, M[9], 21);

		magic[0] = magic[0] + A;
		magic[1] = magic[1] + B;
		magic[2] = magic[2] + C;
		magic[3] = magic[3] + D;
	}
    free(paddedMessage);
	memmove(digest, magic, 16);
}

void sha1_message(const char* message, uint64_t length, uint8_t digest[20])
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
