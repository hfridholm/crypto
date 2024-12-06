#include "../aes.h"
#include "aes-intern.h"

#define LSHIFT(a, b) ((a) << (b))
#define RSHIFT(a, b) ((a) >> (b))

/*
 * b0: 8 bits, b1: 8 bits, b2: 8 bits, b3: 8 bits
 *
 * RotWord([b0, b1, b2, b3]) = [b1, b2, b3, b0]
 */
#define ROTWORD(b) (LSHIFT(b, 8) | RSHIFT(b, 24))

// SBOX shift n bits
#define SBOXS(b, n) LSHIFT(sbox[RSHIFT(b, n) & 0xff], n)

// SBOX on 32-bit word 4 bytes
#define SUBWORD(b) (SBOXS(b, 24) | SBOXS(b, 16) | SBOXS(b, 8) | SBOXS(b, 0))


#define RC(i) ((i) & 0x80 ? ((LSHIFT(i, 1) & 0xff) ^ 0x1b) : (LSHIFT(i, 1) & 0xff))

#define RCON(i) LSHIFT(RC(i), 24)

/*
 * PARAMS
 * - uint32_t* rkeys     | The 32-bit words of the expanded key
 * - const uint32_t* key | The AES key in 32-bit words
 * - ksize_t ksize       | The amount of 32-bit words in the AES key
 * 4 words for AES-128, 6 words for AES-192, 8 words for AES-256
 *
 * RETURN (int status)
 * - 0 | Success
 * - 1 | Invalid key length
 */
int key_expand(uint32_t* rkeys, const uint32_t* key, ksize_t ksize)
{
  if(ksize != AES_128 && ksize != AES_192 && ksize != AES_256) return 1;

  uint8_t rounds = ROUND_KEYS(ksize);

  for(uint8_t index = 0; index < (4 * rounds); index++)
  {
    if(index < ksize)
    {
      rkeys[index] = key[index];
    }
    else if(index % ksize == 0)
    {
      rkeys[index] = rkeys[index - ksize] ^ SUBWORD(ROTWORD(rkeys[index - 1])) ^ RCON(index / ksize);
    }
    else if(index % ksize == 4 && ksize > 6)
    {
      rkeys[index] = rkeys[index - ksize] ^ SUBWORD(rkeys[index - 1]);
    }
    else
    {
      rkeys[index] = rkeys[index - ksize] ^ rkeys[index - 1];
    }
  }
  return 0;
}
