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

  mpz_import(m, size, 1, sizeof(char), -1, 0, message);

  mpz_powm(r, m, key->e, key->n);

  gmp_printf("r: %Zd\n", r);

  mpz_export(result, NULL, 1, sizeof(char), -1, 0, r);

  mpz_clears(m, r, NULL);

  return 0;
}

/*
 *
 */
int rsa_decrypt(void* result, const void* message, size_t size, skey_t* key)
{
  if(size > ENCRYPT_SIZE) return 1;

  size_t import_size = size;

  while(import_size > 0 && ((char*)message)[import_size - 1] == 0x00)
  {
    import_size--;
  }

  printf("import_size: %ld\n", import_size);

  printf("Message: ");
  for(size_t index = 0; index < import_size; index++)
  {
    printf("%x", ((char*) message)[index] & 0xFF);
  }
  printf("\n");

  mpz_t m, r;

  mpz_inits(m, r, NULL);

  mpz_import(m, import_size, 1, sizeof(char), -1, 0, message);

  gmp_printf("m: %Zd\n", m);

  mpz_powm(r, m, key->d, key->n);

  mpz_export(result, NULL, 1, sizeof(char), -1, 0, r);

  mpz_clears(m, r, NULL);

  return 0;
}
