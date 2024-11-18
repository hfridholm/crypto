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
static void base64_skey_decode(skey_t* key, const void* message, size_t size)
{
  char buffer[size];

  size_t buffer_size = base64_decode(buffer, message, size);

  skey_decode(key, buffer, buffer_size);
}

/*
 *
 */
static void base64_pkey_decode(pkey_t* key, const void* message, size_t size)
{
  char buffer[size];

  size_t buffer_size = base64_decode(buffer, message, size);

  pkey_decode(key, buffer, buffer_size);
}

/*
 *
 */
static void pkey_handler(pkey_t* key)
{
  size_t file_size = file_size_get("pkey");

  char base64[file_size];

  file_read(base64, file_size, "pkey");

  base64_pkey_decode(key, base64, file_size);
}

/*
 *
 */
static void skey_handler(skey_t* key)
{
  size_t file_size = file_size_get("skey");

  char base64[file_size];

  file_read(base64, file_size, "skey");

  base64_skey_decode(key, base64, file_size);
}

int main(int argc, char* argv[])
{
  srand(time(NULL));

  skey_t skey;
  pkey_t pkey;

  skey_handler(&skey);

  pkey_handler(&pkey);

  printf("pkey:\n");
  gmp_printf("n: %Zd\n", pkey.n);
  gmp_printf("e: %Zd\n", pkey.e);

  printf("skey:\n");
  gmp_printf("n: %Zd\n", skey.n);
  gmp_printf("e: %Zd\n", skey.e);
  gmp_printf("d: %Zd\n", skey.d);
  gmp_printf("p: %Zd\n", skey.p);
  gmp_printf("q: %Zd\n", skey.q);

  /*
  char message[32] = "This is my password";
  
  printf("message: (%s)\n", message);

  char encrypt[64];
  memset(encrypt, '\0', sizeof(encrypt));

  char decrypt[64];
  memset(decrypt, '\0', sizeof(decrypt));

  rsa_encrypt(encrypt, message, strlen(message), &pkey);
  
  printf("encrypt: (%s)\n", encrypt);

  rsa_decrypt(decrypt, encrypt, strlen(encrypt), &skey);
  
  printf("decrypt: (%s)\n", decrypt);
  */

  keys_free(&skey, &pkey);

  return 0;
}
