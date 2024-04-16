#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#define ROUND_KEYS(n) (((n) == 4) ? 11 : ((n) == 6) ? 13 : 15)

int key_expand(uint32_t* w, const uint32_t* k, uint8_t n);

extern int aes_encrypt(void* result, const void* message, size_t size, const char* key);

extern int aes_decrypt(void* result, const void* message, size_t size, const char* key);

#endif // AES_H
