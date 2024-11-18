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

  printf("pkey:\n");
  gmp_printf("n: %Zd\n", pkey.n);
  gmp_printf("e: %Zd\n", pkey.e);

  printf("skey:\n");
  gmp_printf("n: %Zd\n", skey.n);
  gmp_printf("e: %Zd\n", skey.e);
  gmp_printf("d: %Zd\n", skey.d);
  gmp_printf("p: %Zd\n", skey.p);
  gmp_printf("q: %Zd\n", skey.q);

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

  keys_free(&skey, &pkey);

  return 0;
}
