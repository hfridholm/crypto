#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef enum
{
  AES_128 = 4,
  AES_192 = 6,
  AES_256 = 8
} ksize_t;

extern int aes_encrypt(void* result, size_t* rsize, const void* message, size_t size, const char* key, ksize_t ksize);

extern int aes_decrypt(void* result, size_t* rsize, const void* message, size_t size, const char* key, ksize_t ksize);

#endif // AES_H
