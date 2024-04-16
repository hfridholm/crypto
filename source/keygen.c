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
#include <stdlib.h>

const char SKEY_FILE[] = "key";
const char PKEY_FILE[] = "key.pub";

char dir[128] = "./";
int bytes = 4096;

int main(int argc, char* argv[])
{
  char skey[4096];
  memset(skey, '\0', sizeof(skey));

  char pkey[4096];
  memset(pkey, '\0', sizeof(pkey));

  rsa_base64_create(skey, pkey);

  printf("Private key:\n%s\n", skey);
  printf("Public key:\n%s\n", pkey);

  return 0;
}
