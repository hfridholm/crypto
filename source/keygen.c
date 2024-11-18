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

extern int base64_encode(void* result, const void* message, size_t size);

extern int base64_decode(void* result, const void* message, size_t size);

int main(int argc, char* argv[])
{
  srand(time(NULL));

  skey_t skey;
  pkey_t pkey;

  keys_generate(&skey, &pkey);

  /*
  printf("pkey:\n");
  gmp_printf("n: %Zd\n", pkey.n);
  gmp_printf("e: %Zd\n", pkey.e);
  */

  printf("skey:\n");
  gmp_printf("n: %Zd\n", skey.n);
  gmp_printf("e: %Zd\n", skey.e);
  gmp_printf("d: %Zd\n", skey.d);
  gmp_printf("p: %Zd\n", skey.p);
  gmp_printf("q: %Zd\n", skey.q);

  char skey_buffer[10000];
  memset(skey_buffer, '\0', sizeof(skey_buffer));

  size_t size = 0;

  skey_encode(skey_buffer, &size, &skey);


  char skey_base64[10000];
  memset(skey_base64, '\0', sizeof(skey_base64));

  base64_encode(skey_base64, &skey_buffer, size);

  printf("skey_base64:\n%s\n", skey_base64);



  skey_t tkey;

  char tkey_buffer[10000];
  memset(tkey_buffer, '\0', sizeof(tkey_buffer));

  base64_decode(tkey_buffer, skey_base64, strlen(skey_base64));


  skey_decode(&tkey, tkey_buffer, size);

  printf("tkey:\n");
  gmp_printf("n: %Zd\n", tkey.n);
  gmp_printf("e: %Zd\n", tkey.e);
  gmp_printf("d: %Zd\n", tkey.d);
  gmp_printf("p: %Zd\n", tkey.p);
  gmp_printf("q: %Zd\n", tkey.q);

  skey_free(&tkey);

  keys_free(&skey, &pkey);

  return 0;
}
