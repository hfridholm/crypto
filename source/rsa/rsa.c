#include "../rsa.h"
#include "rsa-intern.h"

/*
 *
 */
int rsa_encrypt(void* result, const void* message, size_t size, pkey_t* key)
{
  if(size > MESSAGE_SIZE) return 1;

  mpz_t m, r;

  mpz_inits(m, r, NULL);

  mpz_import(m, size, 1, sizeof(char), 0, 0, message);

  gmp_printf("m: %Zd\n", m);

  mpz_powm(r, m, key->e, key->n);

  mpz_export(result, NULL, 1, sizeof(char), 0, 0, r);

  mpz_clears(m, r, NULL);

  return 0;
}

/*
 *
 */
int rsa_decrypt(void* result, const void* message, size_t size, skey_t* key)
{
  if(size > MESSAGE_SIZE) return 1;

  mpz_t m, r;

  mpz_inits(m, r, NULL);

  mpz_import(m, size, 1, sizeof(char), 0, 0, message);

  mpz_powm(r, m, key->d, key->n);

  mpz_export(result, NULL, 1, sizeof(char), 0, 0, r);

  mpz_clears(m, r, NULL);

  return 0;
}
