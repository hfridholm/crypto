#include "../aes.h"
#include "aes-intern.h"

/*
 * SubBytes
 */
static void sub_bytes(uint8_t block[16])
{
  for(uint8_t index = 0; index < 16; index++)
  {
    block[index] = sbox[block[index]];
  }
}

/*
 * SubBytes - inverse
 */
static void sub_bytes_inverse(uint8_t block[16])
{
  for(uint8_t index = 0; index < 16; index++)
  {
    block[index] = sbox_inv[block[index]];
  }
}

static void bytes_switch(uint8_t block[16], uint8_t a, uint8_t b)
{
  uint8_t temp = block[a];

  block[a] = block[b];

  block[b] = temp;
}

/*
 * ShiftRows
 */
static void shift_rows(uint8_t block[16])
{
  bytes_switch(block, 4, 5);
  bytes_switch(block, 4, 6);
  bytes_switch(block, 4, 7);

  bytes_switch(block, 8, 10);
  bytes_switch(block, 9, 11);

  bytes_switch(block, 12, 13);
  bytes_switch(block, 12, 14);
  bytes_switch(block, 12, 15);
}

/*
 * ShiftRows - inverse
 */
static void shift_rows_inverse(uint8_t block[16])
{
  bytes_switch(block, 4, 7);
  bytes_switch(block, 4, 6);
  bytes_switch(block, 4, 5);

  bytes_switch(block, 9, 11);
  bytes_switch(block, 8, 10);

  bytes_switch(block, 12, 15);
  bytes_switch(block, 12, 14);
  bytes_switch(block, 12, 13);
}

#define ROW(a, b, c, d)     (a        ^ b         ^ mult2[c]  ^ mult3[d])
#define ROW_INV(a, b, c, d) (mult9[a] ^ mult11[b] ^ mult13[c] ^ mult14[d])

/*
 * MixColumns
 */
static void mix_columns(uint8_t block[16])
{
  for(uint8_t column = 0; column < 4; column++)
  {
    uint8_t a = block[column];
    uint8_t b = block[column +  4];
    uint8_t c = block[column +  8];
    uint8_t d = block[column + 12];

    block[column]      = ROW(c, d, a, b);
    block[column +  4] = ROW(d, a, b, c);
    block[column +  8] = ROW(a, b, c, d);
    block[column + 12] = ROW(b, c, d, a);
  }
}

/*
 * MixColumns - inverse
 */
static void mix_columns_inverse(uint8_t block[16])
{
  for(uint8_t column = 0; column < 4; column++)
  {
    uint8_t a = block[column];
    uint8_t b = block[column +  4];
    uint8_t c = block[column +  8];
    uint8_t d = block[column + 12];

    block[column]      = ROW_INV(d, b, c, a);
    block[column +  4] = ROW_INV(a, c, d, b);
    block[column +  8] = ROW_INV(b, d, a, c);
    block[column + 12] = ROW_INV(c, a, b, d);
  }
}

/*
 * AddRoundKey
 */
static void add_round_key(uint8_t block[16], const uint8_t rkey[16])
{
  for(uint8_t index = 0; index < 16; index++)
  {
    block[index] ^= rkey[index];
  }
}

/*
 *
 */
static void aes_block_encrypt(uint8_t result[16], const uint8_t input[16], const uint8_t* rkeys, uint8_t rounds)
{
  uint8_t block[16];
  memcpy(block, input, 16);

  add_round_key(block, rkeys);

  for(int index = 1; index < (rounds - 2); index++)
  {
    sub_bytes(block);

    shift_rows(block);

    mix_columns(block);
    
    add_round_key(block, rkeys + index * 16);
  }

  sub_bytes(block);

  shift_rows(block);

  add_round_key(block, rkeys + 16 * (rounds - 1));

  memcpy(result, block, 16);
}

/*
 *
 */
static void aes_block_decrypt(uint8_t result[16], const uint8_t input[16], const uint8_t* rkeys, uint8_t rounds)
{
  uint8_t block[16];
  memcpy(block, input, 16);

  add_round_key(block, rkeys + 16 * (rounds - 1));

  shift_rows_inverse(block);

  sub_bytes_inverse(block);

  for(uint8_t index = (rounds - 2); index-- > 1;)
  {
    add_round_key(block, rkeys + 16 * index);

    mix_columns_inverse(block);

    shift_rows_inverse(block);

    sub_bytes_inverse(block);
  }
  
  add_round_key(block, rkeys);

  memcpy(result, block, 16);
}

/*
 * Encrypt message using AES key of different sizes
 *
 * Maybe: Add size_t* rsize argument for result size and rename size to msize
 *
 * RETURN (int status)
 * - 0 | Success
 * - 1 | Failed to expand key
 */
int aes_encrypt(char** result, size_t* rsize, const void* message, size_t msize, const void* key, ksize_t ksize)
{
  if(!result || !message || !key) return 1;

  // 1. Expand the key
  uint8_t rounds = ROUND_KEYS(ksize);

  uint32_t rkeys[4 * rounds];

  if(key_expand(rkeys, (uint32_t*) key, ksize) != 0)
  {
    return 2;
  }

  // 2. Allocate memory for the result (AES message)
  *result = malloc(sizeof(uint8_t) * AES_SIZE(msize));

  if(rsize) *rsize = AES_SIZE(msize);


  // 3. Encrypt the whole blocks in message
  size_t index;
  uint8_t block[16];

  for(index = 0; index + 16 <= msize; index += 16)
  {
    memcpy(block, (uint8_t*) message + index, 16);

    aes_block_encrypt((uint8_t*)(*result) + index, block, (uint8_t*) rkeys, rounds);
  }

  // 4. Encrypt the rest of the message
  if(index < msize)
  {
    memset(block, 0, 16);

    memcpy(block, (uint8_t*) message + index, msize - index);

    aes_block_encrypt((uint8_t*)(*result) + index, block, (uint8_t*) rkeys, rounds);
  }
  
  return 0;
}

/*
 * Decrypt AES message using key of different sizes
 *
 * RETURN (int status)
 * - 0 | Success
 * - 1 | Failed to expand key
 */
int aes_decrypt(char** result, size_t* rsize, const void* message, size_t msize, const void* key, ksize_t ksize)
{
  if(!result || !message || !key) return 1;

  // 1. Expand the key
  uint8_t rounds = ROUND_KEYS(ksize);

  uint32_t rkeys[4 * rounds];

  if(key_expand(rkeys, (uint32_t*) key, ksize) != 0)
  {
    return 2;
  }

  // 2. Allocate memory for the result
  *result = malloc(sizeof(uint8_t) * msize);


  // 3. Decrypt the whole blocks in message
  size_t index;
  uint8_t block[16];

  for(index = 0; index + 16 <= msize; index += 16)
  {
    memcpy(block, (uint8_t*) message + index, 16);

    aes_block_decrypt((uint8_t*)(*result) + index, block, (uint8_t*) rkeys, rounds);
  }

  // 4. Decrypt the rest of the message
  if(index < msize)
  {
    memset(block, 0, 16);

    memcpy(block, (uint8_t*) message + index, msize - index);

    aes_block_decrypt((uint8_t*)(*result) + index, block, (uint8_t*) rkeys, rounds);
  }

  // 5. Get the size of the result, by trimming trailing bytes
  if(rsize)
  {
    *rsize = msize;

    while(*rsize > 0 && ((uint8_t*) *result)[*rsize - 1] == 0x00)
    {
      (*rsize)--;
    }
  }

  return 0;
}
