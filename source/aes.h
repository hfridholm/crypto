#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

typedef enum
{
  AES_NONE = 0,
  AES_128  = 4,
  AES_192  = 6,
  AES_256  = 8
} ksize_t;

#define AES_SIZE(SIZE) (((SIZE) + 15) & ~15)

extern int aes_encrypt(char** result, size_t* rsize, const void* message, size_t msize, const void* key, ksize_t ksize);

extern int aes_decrypt(char** result, size_t* rsize, const void* message, size_t msize, const void* key, ksize_t ksize);

#endif // AES_H
