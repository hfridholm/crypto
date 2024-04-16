/*
 *
 */

#include <stdio.h>
#include "aes.h"

int main(int argc, char* argv[])
{
  printf("encrypt\n");

  uint32_t key[4] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5};

  uint8_t r = ROUND_KEYS(4); 

  uint32_t w[4 * r];

  key_expand(w, key, 4);

  for(int index = 0; index < 4 * r; index += 4)
  {
    printf("%x%x%x%x\n", w[index], w[index + 1], w[index + 2], w[index + 3]);
  }

  return 0;
}
