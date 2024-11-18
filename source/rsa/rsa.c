#include "../rsa.h"
#include "rsa-intern.h"

/*
 *
 */
int rsa_encrypt(void* result, size_t* rsize, const void* message, size_t msize, pkey_t* key)
{
  if(msize > MESSAGE_SIZE) return 1;

  mpz_t m, r;

  mpz_inits(m, r, NULL);

  mpz_import(m, msize, 1, sizeof(char), 0, 0, message);

  mpz_powm(r, m, key->e, key->n);

  mpz_export(result, rsize, 1, sizeof(char), 0, 0, r);

  mpz_clears(m, r, NULL);

  return 0;
}

/*
 *
 */
int rsa_decrypt(void* result, size_t* rsize, const void* message, size_t msize, skey_t* key)
{
  if(msize > MESSAGE_SIZE) return 1;

  mpz_t m, r;

  mpz_inits(m, r, NULL);

  mpz_import(m, msize, 1, sizeof(char), 0, 0, message);

  mpz_powm(r, m, key->d, key->n);

  mpz_export(result, rsize, 1, sizeof(char), 0, 0, r);

  mpz_clears(m, r, NULL);

  return 0;
}
