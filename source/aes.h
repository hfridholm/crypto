#ifndef AES_H
#define AES_H

#include <stdint.h>

#define ROUND_KEYS(n) (((n) == 4) ? 11 : ((n) == 6) ? 13 : 15)

int key_expand(uint32_t* w, const uint32_t* k, uint8_t n);

#endif // AES_H
