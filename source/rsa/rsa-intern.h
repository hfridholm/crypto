#ifndef RSA_INTERN_H
#define RSA_INTERN_H

#define MODULUS_SIZE 1024

#define BUFFER_SIZE ((MODULUS_SIZE / 8) / 2)

#define MESSAGE_SIZE ((MODULUS_SIZE / 8) - 11)

extern void skey_free(skey_t* key);

extern void pkey_free(pkey_t* key);

#endif // RSA_INTERN_H
