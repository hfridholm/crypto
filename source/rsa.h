/*
 * rsa.h - implementation of RSA algorithm
 *
 * Written by Hampus Fridholm
 *
 * Credit:
 * https://en.wikipedia.org/wiki/RSA_(cryptosystem)
 * https://gmplib.org
 *
 * Last updated: 2025-02-25
 *
 *
 * In main compilation unit; define RSA_IMPLEMENT
 *
 *
 * void rsa_keys_gen(skey_t* skey, pkey_t* pkey)
 *
 *
 * int  rsa_encrypt(void* result, size_t* rsize, const void* message, size_t size, pkey_t* key)
 *
 * int  rsa_decrypt(void* result, size_t* rsize, const void* message, size_t size, skey_t* key)
 *
 *
 * int  rsa_skey_encode(char** result, size_t* size, const skey_t* key)
 *
 * int  rsa_skey_decode(skey_t* key, const void* message, size_t size)
 *
 *
 * int  rsa_pkey_encode(char** result, size_t* size, const pkey_t* key)
 *
 * int  rsa_pkey_decode(pkey_t* key, const void* message, size_t size)
 *
 *
 * void rsa_keys_free(skey_t* skey, pkey_t* pkey)
 *
 * void rsa_skey_free(skey_t* key)
 *
 * void rsa_pkey_free(pkey_t* key)
 */

#ifndef RSA_H
#define RSA_H

#include <stdlib.h>
#include <gmp.h>

#define MODULUS_SIZE 512

#define ENCRYPT_SIZE  (MODULUS_SIZE / 8)

#define BUFFER_SIZE  ((MODULUS_SIZE / 8) / 2)

#define MESSAGE_SIZE ((MODULUS_SIZE / 8) - 11)

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

extern void rsa_keys_gen(skey_t* skey, pkey_t* pkey);


extern int  rsa_encrypt(void* result, size_t* rsize, const void* message, size_t size, pkey_t* key);

extern int  rsa_decrypt(void* result, size_t* rsize, const void* message, size_t size, skey_t* key);


extern int  rsa_skey_encode(char** result, size_t* size, const skey_t* key);

extern int  rsa_skey_decode(skey_t* key, const void* message, size_t size);


extern int  rsa_pkey_encode(char** result, size_t* size, const pkey_t* key);

extern int  rsa_pkey_decode(pkey_t* key, const void* message, size_t size);


extern void rsa_keys_free(skey_t* skey, pkey_t* pkey);

extern void rsa_skey_free(skey_t* key);

extern void rsa_pkey_free(pkey_t* key);

#endif // RSA_H

/*
 * This header library file uses _IMPLEMENT guards
 *
 * If RSA_IMPLEMENT is defined, the definitions will be included
 */

#ifdef RSA_IMPLEMENT

#include <stdio.h>
#include <string.h>
#include <errno.h>

/*
 * Duplicate a mpz_t variable
 */
static inline void mpz_dup(mpz_t dest, const mpz_t src)
{
  mpz_init(dest);

  mpz_set(dest, src);
}

/*
 * Calculate phi: (p - 1)(q - 1)
 */
static inline void mpz_phi(mpz_t phi, const mpz_t p, const mpz_t q)
{
  mpz_t tp, tq;

  mpz_inits(tp, tq, NULL);

  mpz_sub_ui(tp, p, 1);
  mpz_sub_ui(tq, q, 1);

  mpz_mul(phi, tp, tq);

  mpz_clears(tp, tq, NULL);
}

/*
 * Choose the private exponent d
 *
 * It can happen that there is no valid d
 *
 * RETURN (int status)
 * - 0 | Success
 * - 1 | No valid d exists
 */
static inline int rsa_choose_d(mpz_t d, const mpz_t e, const mpz_t phi)
{
  if (mpz_invert(d, e, phi) != 0) return 0;

  mpz_t tmp;
  mpz_init(tmp);

  mpz_gcd(tmp, e, phi);

  gmp_printf("gcd(e, phi) = [%Zs]\n", tmp);

  mpz_clear(tmp);

  return 1;
}

/*
 * Generate a random prime number
 *
 * CREDIT
 * https://github.com/gilgad13/rsa-gmp/blob/master/rsa.c
 *
 * PARAMS
 * - mpz_t prime | The prime number
 *
 * EXPECT
 * - prime is initted and allocated
 */
static inline void rsa_prime_gen(mpz_t prime)
{
  char buffer[BUFFER_SIZE];

  for (int index = 0; index < BUFFER_SIZE; index++)
  {
    buffer[index] = rand() % 0xFF;
  }

  buffer[0] |= 0xC0;

  buffer[BUFFER_SIZE - 1] |= 0x01;

  mpz_t tmp;
  mpz_init(tmp);

  mpz_import(tmp, BUFFER_SIZE, 1, sizeof(buffer[0]), 0, 0, buffer);

  mpz_nextprime(prime, tmp);

  mpz_clear(tmp);
}

/*
 * Tweak the prime number to be a good choise
 */
static inline void rsa_prime_tweak(mpz_t prime, mpz_t e)
{
  mpz_t tmp;
  mpz_init(tmp);

  mpz_mod(tmp, prime, e);

  // prime must not be congruent to 1 mod e
  while (mpz_cmp_ui(tmp, 1) == 0)
  {
    mpz_nextprime(prime, prime);

    mpz_mod(tmp, prime, e);
  }

  mpz_clear(tmp);
}

/*
 * Generate the two large primes p and q
 *
 * The primes should be good, based on exponent e
 *
 * The primes should not be the same number
 */
static inline void rsa_primes_gen(mpz_t p, mpz_t q, mpz_t e)
{
  rsa_prime_gen(p);

  rsa_prime_tweak(p, e);

  do
  {
    rsa_prime_gen(q);

    rsa_prime_tweak(q, e);
  }
  while (mpz_cmp(p, q) == 0);
}

/*
 * Generate the p, q, n, e and d values needed for the keys
 *
 * Probably: Only do the operation once, and remove the for loop
 */
static inline void rsa_key_values_gen(mpz_t p, mpz_t q, mpz_t n, mpz_t e, mpz_t d, mpz_t phi)
{
  // 1. Choose e
  mpz_set_ui(e, 3);

  for (size_t count = 1; count <= 100; count++)
  {
    // 2. Generate large primes p and q
    rsa_primes_gen(p, q, e);

    // 3. Multiply p and q to get n
    mpz_mul(n, p, q);

    // 4. Calculate phi
    mpz_phi(phi, p, q);

    // 5. Choose d
    if (rsa_choose_d(d, e, phi) == 0) break;

    printf("Failed to generate key values: %ld\n", count);
  }
}

/*
 * Generate the secret and the public keys
 */
void rsa_keys_gen(skey_t* skey, pkey_t* pkey)
{
  mpz_t p, q, n, e, d, phi;

  mpz_inits(p, q, n, e, d, phi, NULL);

  rsa_key_values_gen(p, q, n, e, d, phi);

  if (pkey)
  {
    mpz_dup(pkey->n, n);
    mpz_dup(pkey->e, e);
  }

  if (skey)
  {
    mpz_dup(skey->n, n);
    mpz_dup(skey->e, e);
    mpz_dup(skey->d, d);
    mpz_dup(skey->p, p);
    mpz_dup(skey->q, q);
  }

  mpz_clears(p, q, n, e, d, phi, NULL);
}

/*
 * Free the secret and the public keys
 */
void rsa_keys_free(skey_t* skey, pkey_t* pkey)
{
  if (pkey) rsa_pkey_free(pkey);

  if (skey) rsa_skey_free(skey);
}

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
int rsa_pkey_encode(char** result, size_t* size, const pkey_t* key)
{
  if (!result || !size || !key)
  {
    errno = EFAULT; // Bad address

    return 1;
  }

  // 1. Serialize the public key cryptography values
  pkey_enc_t key_enc = { 0 };

  mpz_export(key_enc.n, &key_enc.ns, 1, sizeof(char), 0, 0, key->n);

  mpz_export(key_enc.e, &key_enc.es, 1, sizeof(char), 0, 0, key->e);


  // 2. Allocate and populate result
  size_t result_size = sizeof(pkey_enc_t);

  char* temp_result = malloc(sizeof(char) * result_size);

  if (!temp_result)
  {
    errno = ENOMEM; // Out of memory

    return 2;
  }

  *result = temp_result;

  if (size) *size = result_size;

  memcpy(*result, &key_enc, sizeof(pkey_enc_t));

  return 0;
}

/*
 * Initialize public key struct variables
 */
static inline void rsa_pkey_init(pkey_t* key)
{
  mpz_init(key->n);
  mpz_init(key->e);
}

/*
 * Free public key struct variables
 */
void rsa_pkey_free(pkey_t* key)
{
  mpz_clear(key->n);
  mpz_clear(key->e);
}

/*
 * Decode encoded public key struct
 */
int rsa_pkey_decode(pkey_t* key, const void* message, size_t size)
{
  if (!key || !message)
  {
    errno = EFAULT; // Bad address

    return 1;
  }

  if (size != sizeof(pkey_enc_t))
  {
    errno = EINVAL; // Invalid argument

    return 2;
  }

  pkey_enc_t key_enc = { 0 };

  memcpy(&key_enc, message, sizeof(pkey_enc_t));

  rsa_pkey_init(key);

  mpz_import(key->n, key_enc.ns, 1, sizeof(char), 0, 0, key_enc.n);

  mpz_import(key->e, key_enc.es, 1, sizeof(char), 0, 0, key_enc.e);

  return 0;
}

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
int rsa_skey_encode(char** result, size_t* size, const skey_t* key)
{
  if (!result || !size || !key)
  {
    errno = EFAULT; // Bad address

    return 1;
  }

  // 1. Serialize the secret key cryptography values
  skey_enc_t key_enc = { 0 };

  mpz_export(key_enc.n, &key_enc.ns, 1, sizeof(char), 0, 0, key->n);

  mpz_export(key_enc.e, &key_enc.es, 1, sizeof(char), 0, 0, key->e);

  mpz_export(key_enc.d, &key_enc.ds, 1, sizeof(char), 0, 0, key->d);

  mpz_export(key_enc.p, &key_enc.ps, 1, sizeof(char), 0, 0, key->p);

  mpz_export(key_enc.q, &key_enc.qs, 1, sizeof(char), 0, 0, key->q);


  // 2. Allocate and populate memory of result
  size_t result_size = sizeof(skey_enc_t);

  char* temp_result = malloc(sizeof(char) * result_size);

  if (!temp_result)
  {
    errno = ENOMEM; // Out of memory

    return 2;
  }

  *result = temp_result;

  if (size) *size = result_size;

  memcpy(*result, &key_enc, sizeof(skey_enc_t));

  return 0;
}

/*
 * Initialize secret key struct variables
 */
static inline void rsa_skey_init(skey_t* key)
{
  mpz_init(key->n);
  mpz_init(key->e);
  mpz_init(key->d);
  mpz_init(key->p);
  mpz_init(key->q);
}

/*
 * Free secret key struct variables
 */
void rsa_skey_free(skey_t* key)
{
  mpz_clear(key->n);
  mpz_clear(key->e);
  mpz_clear(key->d);
  mpz_clear(key->p);
  mpz_clear(key->q);
}

/*
 * Decode encoded secret key struct
 */
int rsa_skey_decode(skey_t* key, const void* message, size_t size)
{
  if (!key || !message)
  {
    errno = EFAULT; // Bad address

    return 1;
  }

  if (size != sizeof(skey_enc_t))
  {
    errno = EINVAL; // Invalid argument

    return 2;
  }

  skey_enc_t key_enc = { 0 };

  memcpy(&key_enc, message, sizeof(skey_enc_t));

  rsa_skey_init(key);

  mpz_import(key->n, key_enc.ns, 1, sizeof(char), 0, 0, key_enc.n);

  mpz_import(key->e, key_enc.es, 1, sizeof(char), 0, 0, key_enc.e);

  mpz_import(key->d, key_enc.ds, 1, sizeof(char), 0, 0, key_enc.d);

  mpz_import(key->p, key_enc.ps, 1, sizeof(char), 0, 0, key_enc.p);

  mpz_import(key->q, key_enc.qs, 1, sizeof(char), 0, 0, key_enc.q);

  return 0;
}

/*
 * Encrypt message using RSA public key
 */
int rsa_encrypt(void* result, size_t* rsize, const void* message, size_t size, pkey_t* key)
{
  if (size > MESSAGE_SIZE)
  {
    errno = EINVAL; // Invalid argument

    return 1;
  }

  mpz_t m, r;

  mpz_inits(m, r, NULL);

  mpz_import(m, size, 1, sizeof(char), 0, 0, message);

  mpz_powm(r, m, key->e, key->n);

  /*
  gmp_printf("m: %Zd\n", m);
  gmp_printf("d: %ld\n", mpz_sizeinbase(key->e, 2));
  gmp_printf("n: %ld\n", mpz_sizeinbase(key->n, 2));
  gmp_printf("r: %Zd\n", r);
  */

  mpz_export(result, rsize, 1, sizeof(char), 0, 0, r);

  mpz_clears(m, r, NULL);

  return 0;
}

/*
 * Decrypt encrypted message using RSA secret key (private key)
 */
int rsa_decrypt(void* result, size_t* rsize, const void* message, size_t size, skey_t* key)
{
  if (size > ENCRYPT_SIZE)
  {
    errno = EINVAL; // Invalid argument

    return 1;
  }

  mpz_t m, r;

  mpz_inits(m, r, NULL);

  mpz_import(m, size, 1, sizeof(char), 0, 0, message);

  mpz_powm(r, m, key->d, key->n);

  /*
  gmp_printf("m: %Zd\n", m);
  gmp_printf("d: %ld\n", mpz_sizeinbase(key->d, 2));
  gmp_printf("n: %ld\n", mpz_sizeinbase(key->n, 2));
  gmp_printf("r: %Zd\n", r);
  */

  mpz_export(result, rsize, 1, sizeof(char), 0, 0, r);

  mpz_clears(m, r, NULL);

  return 0;
}

#endif // RSA_IMPLEMENT
