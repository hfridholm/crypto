/*
 * rsa.h
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-11-17
 */

#ifndef RSA_H
#define RSA_H

#include <stdlib.h>
#include <gmp.h>
#include <stdio.h>

typedef struct
{
  mpz_t n; // Modulus
  mpz_t e; // Public exponent
} pkey_t;

typedef struct
{
  mpz_t n; // Modulus
  mpz_t e; // Public exponent
  mpz_t d; // Private exponent
  mpz_t p; // Prime p
  mpz_t q; // Prime q
} skey_t;

extern int  keys_generate(skey_t* skey, pkey_t* pkey);

extern void keys_free(skey_t* skey, pkey_t* pkey);


extern int rsa_encrypt(void* result, const void* message, size_t size, pkey_t* key);

extern int rsa_decrypt(void* result, const void* message, size_t size, skey_t* key);

#endif // RSA_H
