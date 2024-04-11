#include "../rsa.h"

const size_t COUNT_MAX = 100;

void mpz_phi(mpz_t phi, const mpz_t p, const mpz_t q)
{
  mpz_t tp, tq;

  mpz_inits(tp, tq, NULL);

  mpz_sub_ui(tp, p, 1);
  mpz_sub_ui(tq, q, 1);

  mpz_mul(phi, tp, tq);

  mpz_clears(tp, tq, NULL);
}

void choose_e(mpz_t e, const mpz_t phi)
{
  // 1. Initialize e at starting point
  mpz_set_ui(e, 2);

  mpz_t gcd;
  mpz_init(gcd);

  for(size_t count = 0; count < COUNT_MAX; count++)
  {
    mpz_gcd(gcd, e, phi);

    if(mpz_cmp_ui(gcd, 1) == 0) break;

    if(mpz_cmp(e, phi) >= 0) break;

    mpz_add_ui(e, e, 1);
  }

  mpz_clear(gcd);
}

void choose_d(mpz_t d, const mpz_t e, const mpz_t phi)
{
  // 1. Initialize d at starting point
  mpz_set_ui(d, 1);
  
  mpz_t t, mod;
  mpz_inits(t, mod, NULL);

  for(size_t count = 0; count < COUNT_MAX; count++)
  {
    mpz_mul(t, e, d);

    mpz_mod(mod, t, phi);

    if(mpz_cmp_ui(mod, 1) == 0) break;

    mpz_add_ui(d, d, 1);
  }

  mpz_clears(t, mod, NULL);
}

void rsa_values_create(mpz_t p, mpz_t q, mpz_t n, mpz_t e, mpz_t d)
{
  // 1. Choose large primes p and q
  // Replace these assignments with generating large random primes
  mpz_set_ui(p, 2);
  mpz_set_ui(q, 7);

  // 2. Multiply p and q to get n
  mpz_mul(n, p, q);

  // 3. Choose e
  mpz_t phi;
  mpz_init(phi);

  mpz_phi(phi, p, q);

  choose_e(e, phi);

  // 4. Choose d
  choose_d(d, e, phi);

  mpz_clear(phi);
}

void rsa_base64_create(char* skey, char* pkey)
{
  mpz_t p, q, n, e, d;

  mpz_inits(p, q, n, e, d, NULL);

  rsa_values_create(p, q, n, e, d);

  gmp_printf("p: %Zd\n", p);
  gmp_printf("q: %Zd\n", q);
  gmp_printf("n: %Zd\n", n);
  gmp_printf("e: %Zd\n", e);
  gmp_printf("d: %Zd\n", d);

  mpz_clears(p, q, n, e, d, NULL);
}

void rsa_base64_encrypt(void* encrypt, const void* pointer, size_t size, char* pkey);

void rsa_base64_decrypt(void* decrypt, const void* pointer, size_t size, char* skey);
