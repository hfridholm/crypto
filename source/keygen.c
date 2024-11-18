/*
 * keygen -b 4096 -d ~/Desktop/keys/
 *
 * -b, --bytes | The amount of bytes
 * -d, --dir   | Where to create the key files
 */

#include "file.h"
#include "rsa.h"
#include "aes.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

extern size_t base64_encode(void* result, const void* message, size_t size);

extern size_t base64_decode(void* result, const void* message, size_t size);

/*
 *
 */
static size_t skey_base64_encode(void* result, const skey_t* key)
{
  char buffer[10000];
  memset(buffer, '\0', sizeof(buffer));

  size_t size = 0;

  skey_encode(buffer, &size, key);

  printf("size: %ld\n", size);

  return base64_encode(result, &buffer, size);
}

/*
 *
 */
static size_t pkey_base64_encode(void* result, const pkey_t* key)
{
  char buffer[10000];
  memset(buffer, '\0', sizeof(buffer));

  size_t size = 0;

  pkey_encode(buffer, &size, key);

  return base64_encode(result, &buffer, size);
}

/*
 *
 */
static void pkey_handler(pkey_t* key)
{
  char buffer[10000];
  memset(buffer, '\0', sizeof(buffer));

  size_t size = pkey_base64_encode(buffer, key);

  file_write(buffer, size, "pkey");
}

/*
 *
 */
static void skey_handler(skey_t* key)
{
  char buffer[10000];
  memset(buffer, '\0', sizeof(buffer));

  size_t size = skey_base64_encode(buffer, key);

  file_write(buffer, size, "skey");
}

/*
 *
 */
int main(int argc, char* argv[])
{
  srand(time(NULL));

  skey_t skey;
  pkey_t pkey;

  keys_generate(&skey, &pkey);

  printf("pkey:\n");
  gmp_printf("n: %Zd\n", pkey.n);
  gmp_printf("e: %Zd\n", pkey.e);

  printf("skey:\n");
  gmp_printf("n: %Zd\n", skey.n);
  gmp_printf("e: %Zd\n", skey.e);
  gmp_printf("d: %Zd\n", skey.d);
  gmp_printf("p: %Zd\n", skey.p);
  gmp_printf("q: %Zd\n", skey.q);


  pkey_handler(&pkey);

  skey_handler(&skey);


  keys_free(&skey, &pkey);

  return 0;
}
