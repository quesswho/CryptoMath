#pragma once

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

void md5_message(const char* message, const size_t length, uint8_t digest[16]);

void md5_block(const uint32_t block[16], uint32_t digest[4]);

void sha1_message(const char* message, const size_t length, uint8_t digest[20]);
