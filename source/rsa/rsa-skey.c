#include "../rsa.h"
#include "rsa-intern.h"

typedef struct
{
  size_t ns;
  char   n[ENCRYPT_SIZE];
  size_t es;
  char   e[1];
  size_t ds;
  char   d[ENCRYPT_SIZE];
  size_t ps;
  char   p[BUFFER_SIZE];
  size_t qs;
  char   q[BUFFER_SIZE];
} skey_enc_t;

/*
 * It is important to initialize the skey_enc_t to 0,
 * otherwise the result would be written uninitialized values
 *
 * The function allocates memory to result, that has to be freed
 */
int skey_encode(char** result, size_t* size, const skey_t* key)
{
  if(!result || !size || !key) return 1;

  // 1. Serialize the secret key cryptography values
  skey_enc_t key_enc = { 0 };

  mpz_export(key_enc.n, &key_enc.ns, 1, sizeof(char), 0, 0, key->n);

  mpz_export(key_enc.e, &key_enc.es, 1, sizeof(char), 0, 0, key->e);

  mpz_export(key_enc.d, &key_enc.ds, 1, sizeof(char), 0, 0, key->d);

  mpz_export(key_enc.p, &key_enc.ps, 1, sizeof(char), 0, 0, key->p);

  mpz_export(key_enc.q, &key_enc.qs, 1, sizeof(char), 0, 0, key->q);


  // 2. Allocate and populate memory of result
  size_t result_size = sizeof(skey_enc_t);

  if(size) *size = result_size;

  *result = malloc(sizeof(char) * result_size);

  memcpy(*result, &key_enc, sizeof(skey_enc_t));

  return 0;
}

/*
 *
 */
void skey_init(skey_t* key)
{
  mpz_init(key->n);
  mpz_init(key->e);
  mpz_init(key->d);
  mpz_init(key->p);
  mpz_init(key->q);
}

/*
 *
 */
void skey_free(skey_t* key)
{
  mpz_clear(key->n);
  mpz_clear(key->e);
  mpz_clear(key->d);
  mpz_clear(key->p);
  mpz_clear(key->q);
}

/*
 *
 */
int skey_decode(skey_t* key, const void* message, size_t size)
{
  if(!key || !message) return 1;

  if(size != sizeof(skey_enc_t)) return 2;

  skey_enc_t key_enc = { 0 };

  memcpy(&key_enc, message, sizeof(skey_enc_t));

  skey_init(key);

  mpz_import(key->n, key_enc.ns, 1, sizeof(char), 0, 0, key_enc.n);
  
  mpz_import(key->e, key_enc.es, 1, sizeof(char), 0, 0, key_enc.e);
  
  mpz_import(key->d, key_enc.ds, 1, sizeof(char), 0, 0, key_enc.d);
  
  mpz_import(key->p, key_enc.ps, 1, sizeof(char), 0, 0, key_enc.p);
  
  mpz_import(key->q, key_enc.qs, 1, sizeof(char), 0, 0, key_enc.q);
  
  return 0;
}
