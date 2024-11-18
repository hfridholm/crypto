#include "../rsa.h"
#include "rsa-intern.h"

typedef struct
{
  size_t ns;
  char   n[128];
  size_t es;
  char   e[1];
} pkey_enc_t;

/*
 *
 */
int pkey_encode(void* result, size_t* size, const pkey_t* key)
{
  if(!result || !size || !key) return 1;

  pkey_enc_t key_enc;

  mpz_export(key_enc.n, &key_enc.ns, 1, sizeof(char), 0, 0, key->n);

  mpz_export(key_enc.e, &key_enc.es, 1, sizeof(char), 0, 0, key->e);

  memcpy(result, &key_enc, sizeof(pkey_enc_t));

  *size = sizeof(pkey_enc_t);

  return 0;
}

/*
 *
 */
void pkey_init(pkey_t* key)
{
  mpz_init(key->n);
  mpz_init(key->e);
}

/*
 *
 */
void pkey_free(pkey_t* key)
{
  mpz_clear(key->n);
  mpz_clear(key->e);
}

/*
 *
 */
int pkey_decode(pkey_t* key, const void* message, size_t size)
{
  if(!key || !message) return 1;

  if(size != sizeof(pkey_enc_t)) return 2;

  pkey_enc_t key_enc = { 0 };

  memcpy(&key_enc, message, sizeof(pkey_enc_t));

  pkey_init(key);

  mpz_import(key->n, key_enc.ns, 1, sizeof(char), 0, 0, key_enc.n);
  
  mpz_import(key->e, key_enc.es, 1, sizeof(char), 0, 0, key_enc.e);
  
  return 0;
}
