#include "../rsa.h"

#define MODULUS_SIZE 1024

#define BUFFER_SIZE (((MODULUS_SIZE) / 8) / 2)

/*
 * Duplicate a mpz_t variable
 */
static void mpz_dup(mpz_t dest, const mpz_t src)
{
  mpz_init(dest);

  mpz_set(dest, src);
}

/*
 * Calculate phi: (p - 1)(q - 1)
 */
static void mpz_phi(mpz_t phi, const mpz_t p, const mpz_t q)
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
static int choose_d(mpz_t d, const mpz_t e, const mpz_t phi)
{
  if(mpz_invert(d, e, phi) != 0) return 0;

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
static void prime_generate(mpz_t prime)
{
  char buffer[BUFFER_SIZE];

  for(int index = 0; index < BUFFER_SIZE; index++)
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
static void prime_tweak(mpz_t prime, mpz_t e)
{
  mpz_t tmp;
  mpz_init(tmp);

  mpz_mod(tmp, prime, e);

  while(!mpz_cmp_ui(tmp, 1))
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
static void primes_generate(mpz_t p, mpz_t q, mpz_t e)
{
  prime_generate(p);

  prime_tweak(p, e);

  do
  {
    prime_generate(q);

    prime_tweak(p, e);
  }
  while(mpz_cmp(p, q) == 0);
}

/*
 * Generate the p, q, n, e and d values needed for the keys
 */
static void key_values_generate(mpz_t p, mpz_t q, mpz_t n, mpz_t e, mpz_t d, mpz_t phi)
{
  // 1. Choose e
  mpz_set_ui(e, 3);

  for(size_t count = 1; count <= 100; count++)
  {
    // 2. Generate large primes p and q
    primes_generate(p, q, e);

    // 3. Multiply p and q to get n
    mpz_mul(n, p, q);

    // 4. Calculate phi
    mpz_phi(phi, p, q);

    // 5. Choose d
    if(choose_d(d, e, phi) == 0) break;

    printf("Failed to generate key values: %ld\n", count);
  }
}

/*
 * Generate the secret and the public keys
 */
int keys_generate(skey_t* skey, pkey_t* pkey)
{
  mpz_t p, q, n, e, d, phi;

  mpz_inits(p, q, n, e, d, phi, NULL);

  key_values_generate(p, q, n, e, d, phi);

  if(pkey)
  {
    mpz_dup(pkey->n, n);
    mpz_dup(pkey->e, e);
  }

  if(skey)
  {
    mpz_dup(skey->n, n);
    mpz_dup(skey->e, e);
    mpz_dup(skey->d, d);
    mpz_dup(skey->p, p);
    mpz_dup(skey->q, q);
  }

  mpz_clears(p, q, n, e, d, phi, NULL);

  return 0;
}

/*
 * Free the secret and the public keys
 */
void keys_free(skey_t* skey, pkey_t* pkey)
{
  if(pkey)
  {
    mpz_clear(pkey->n);
    mpz_clear(pkey->e);
  }

  if(skey)
  {
    mpz_clear(skey->n);
    mpz_clear(skey->e);
    mpz_clear(skey->d);
    mpz_clear(skey->p);
    mpz_clear(skey->q);
  }
}
