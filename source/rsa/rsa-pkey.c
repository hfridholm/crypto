#include "../rsa.h"
#include "rsa-intern.h"

typedef struct
{
  size_t ns;
  char   n[ENCRYPT_SIZE];
  size_t es;
  char   e[1];
} pkey_enc_t;

/*
 * It is important to initialize the skey_enc_t to 0,
 * otherwise the result would be written uninitialized values
 *
 * The function allocates memory to result, that has to be freed
 */
int pkey_encode(char** result, size_t* size, const pkey_t* key)
{
  if(!result || !size || !key) return 1;

  // 1. Serialize the public key cryptography values
  pkey_enc_t key_enc = { 0 };

  mpz_export(key_enc.n, &key_enc.ns, 1, sizeof(char), 0, 0, key->n);

  mpz_export(key_enc.e, &key_enc.es, 1, sizeof(char), 0, 0, key->e);


  // 2. Allocate and populate result
  size_t result_size = sizeof(pkey_enc_t);

  if(size) *size = result_size;

  *result = malloc(sizeof(char) * result_size);

  memcpy(*result, &key_enc, sizeof(pkey_enc_t));

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
