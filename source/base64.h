#ifndef BASE64_H
#define BASE64_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern int base64_encode(char** result, size_t* rsize, const void* message, size_t msize);

extern int base64_decode(char** result, size_t* rsize, const void* message, size_t msize);

#endif // BASE64_H
