#ifndef AES_INTERN_H
#define AES_INTERN_H

extern const uint8_t sbox[256];
extern const uint8_t sbox_inv[256];

extern const uint8_t mult2[256];
extern const uint8_t mult3[256];
extern const uint8_t mult9[256];
extern const uint8_t mult11[256];
extern const uint8_t mult13[256];
extern const uint8_t mult14[256];

#define ROUND_KEYS(n) (((n) == 4) ? 11 : ((n) == 6) ? 13 : 15)

extern int key_expand(uint32_t* rkeys, const uint32_t* key, ksize_t ksize);

#endif // AES_INTERN_H
