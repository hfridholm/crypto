#include "../rsa.h"
#include "rsa-intern.h"

/*
 *
 */
int rsa_encrypt(void* result, size_t* rsize, const void* message, size_t size, pkey_t* key)
{
  if(size > MESSAGE_SIZE) return 1;

  mpz_t m, r;

  mpz_inits(m, r, NULL);

  mpz_import(m, size, 1, sizeof(char), 0, 0, message);

  mpz_powm(r, m, key->e, key->n);

  gmp_printf("m: %Zd\n", m);
  gmp_printf("r: %Zd\n", r);
  gmp_printf("e: %Zd\n", key->e);
  gmp_printf("n: %Zd\n", key->n);

  mpz_export(result, rsize, 1, sizeof(char), 0, 0, r);

  mpz_clears(m, r, NULL);

  return 0;
}

/*
 *
 */
int rsa_decrypt(void* result, size_t* rsize, const void* message, size_t size, skey_t* key)
{
  if(size > ENCRYPT_SIZE) return 1;

  mpz_t m, r;

  mpz_inits(m, r, NULL);

  mpz_import(m, size, 1, sizeof(char), 0, 0, message);

  mpz_powm(r, m, key->d, key->n);

  gmp_printf("m: %Zd\n", m);
  gmp_printf("r: %Zd\n", r);
  gmp_printf("d: %Zd\n", key->d);
  gmp_printf("n: %Zd\n", key->n);

  mpz_export(result, rsize, 1, sizeof(char), 0, 0, r);

  mpz_clears(m, r, NULL);

  return 0;
}
