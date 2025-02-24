/*
 * sha256.h - implementation of the SHA256 algorithm
 *
 * Written by Hampus Fridholm
 *
 * Credit: https://sha256algorithm.com
 *
 * Last updated: 2024-12-06
 *
 *
 * In main compilation unit; define SHA256_IMPLEMENT
 *
 *
 * These are the available funtions:
 *
 * char* sha256(char hash[64], const void* message, size_t size)
 */

/*
 * From here on, until SHA256_IMPLEMENT,
 * it is like a normal header file with declarations
 */

#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>

extern char* sha256(char hash[64], const void* message, size_t size);

#endif // SHA256_H

/*
 * This header library file uses _IMPLEMENT guards
 *
 * If SHA256_IMPLEMENT is defined, the definitions will be included
 */

#ifdef SHA256_IMPLEMENT

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * Create a SHA256 hash of the inputted "h"-values
 *
 * PARAMS
 * - char hash[64]      | A pointer to the "will be created"-hash
 * - const uint32 hs[8] | The "h"-values which to create the hash from
 *
 * RETURN (char* hash)
 */
static inline char* sha_hs_hash(char hash[64], const uint32_t hs[8])
{
  char temp_hash[64 + 1];

  for(uint8_t index = 0; index < 8; index++)
  {
    sprintf(temp_hash + (index * 8), "%08x", hs[index]);
  }

  strncpy(hash, temp_hash, sizeof(char) * 64);

  return hash;
}

#define SHA_LSHIFT(a, b) ((a) << (b))
#define SHA_RSHIFT(a, b) ((a) >> (b))

#define SHA_RROTATE(a, b) (SHA_RSHIFT(a, b) | SHA_LSHIFT(a, 32 - (b)))

#define SHA_SIG0(x) (SHA_RROTATE(x, 7) ^ SHA_RROTATE(x, 18) ^ SHA_RSHIFT(x, 3))
#define SHA_SIG1(x) (SHA_RROTATE(x, 17) ^ SHA_RROTATE(x, 19) ^ SHA_RSHIFT(x, 10))

/*
 * Create a 64-entry message schedule array w[0..63] of 32-bit words
 *
 * PARAMS
 * - uint32_t w[64]     | The message schedule array w
 * - uint32_t chunk[16] | The chunk from which to create the schedule array
 */
static inline void sha_w_create(uint32_t w[64], const uint32_t chunk[16])
{
  // 1. Copy 1st chunk into 1st 16 words w[0..15] of the message schedule array
  memcpy(w, chunk, 64);

  for(uint8_t index = 16; index < 64; index++)
  {
    uint32_t word1 = w[index - 16];
    uint32_t word2 = SHA_SIG0(w[index - 15]);
    uint32_t word3 = w[index - 7];
    uint32_t word4 = SHA_SIG1(w[index - 2]);

    w[index] = word1 + word2 + word3 + word4;
  }
}

#define SHA_CHOISE(e, f, g) (((e) & (f)) ^ (~(e) & (g)))
#define SHA_MAJORITY(a, b, c) (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))

#define SHA_SUM0(x) (SHA_RROTATE(x, 2) ^ SHA_RROTATE(x, 13) ^ SHA_RROTATE(x, 22))
#define SHA_SUM1(x) (SHA_RROTATE(x, 6) ^ SHA_RROTATE(x, 11) ^ SHA_RROTATE(x, 25))

// first 32 bits of the fractional parts of the cube roots of the first 64 primes
static const uint32_t SHA_K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/*
 * Update the "h"-values with the generated words
 *
 * PARAMS
 * - uint32_t hs[8]       | The "will be updated"-"h" values
 * - const uint32_t w[64] | The 64-entry message schedule array
 */
static inline void sha_hs_w_update(uint32_t hs[8], const uint32_t w[64])
{
  // Initialize working variables to initial hash value
  uint32_t a = hs[0];
  uint32_t b = hs[1];
  uint32_t c = hs[2];
  uint32_t d = hs[3];
  uint32_t e = hs[4];
  uint32_t f = hs[5];
  uint32_t g = hs[6];
  uint32_t h = hs[7];

  // Update working variables as:
  for(uint8_t index = 0; index < 64; index++)
  {
    uint32_t majority = SHA_MAJORITY(a, b, c);
    uint32_t choise   = SHA_CHOISE(e, f, g);

    uint32_t sum0 = SHA_SUM0(a);
    uint32_t sum1 = SHA_SUM1(e);

    uint32_t t1 = h + sum1 + choise + SHA_K[index] + w[index];
    uint32_t t2 = sum0 + majority;

    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  // Add the working variables to the current hash value
  hs[0] += a;
  hs[1] += b;
  hs[2] += c;
  hs[3] += d;
  hs[4] += e;
  hs[5] += f;
  hs[6] += g;
  hs[7] += h;
}

/*
 * Update the "h"-values with the bits in the inputted chunk
 *
 * PARAMS
 * - uint32_t hs[8]           | The "will be updated" "h"-values
 * - const uint32_t chunk[16] | The current chunk from the block
 */
static inline void sha_hs_chunk_update(uint32_t hs[8], const uint32_t chunk[16])
{
  uint32_t w[64];

  // 1. Create a 64-entry message schedule array w[0..63] of 32-bit words
  sha_w_create(w, chunk);

  // 2. Update the "h"-values with the created message schedule array
  sha_hs_w_update(hs, w);
}

/*
 * These bit manipulation macros is ment for 32-bit words
 *
 * BIT refers to the bit in the words at a specific index
 */

// Note: (BIT >> 5) is equivalent to (BIT / 32)
#define SHA_BIT_WORD(WORDS, BIT) (WORDS)[(BIT) >> 5]

// Note: (BIT & 0b11111) is equivalent to (BIT % 32)
#define SHA_WORD_BIT(BIT) (31 - ((BIT) & 0b11111))

#define SHA_BIT_SET(WORDS, BIT) (SHA_BIT_WORD(WORDS, BIT) |=  SHA_LSHIFT(1, SHA_WORD_BIT(BIT)))

#define SHA_BIT_OFF(WORDS, BIT) (SHA_BIT_WORD(WORDS, BIT) &= ~SHA_LSHIFT(1, SHA_WORD_BIT(BIT)))

/*
 * Prepend the binary representation of the message to the message block
 *
 * PARAMS
 * - uint32_t* block     | The message block to prepend the message to
 * - const void* message | The message to prepend
 * - size_t size         | The amount of bytes (8 bits)
 */
static inline void sha_block_message_prepend(uint32_t* block, const void* message, size_t size)
{
  for(size_t index = 0; index < size; index++)
  {
    for(uint8_t bit = 0; bit < 8; bit++)
    {
      char word = ((char*) message)[index];

      if(word & SHA_LSHIFT(1, (7 - bit)))
      {
        SHA_BIT_SET(block, (index * 8) + bit);
      }
      else SHA_BIT_OFF(block, (index * 8) + bit);
    }
  }
}

/*
 * Calculate the initial amount of chunks (no extra chunk)
 *
 * This is the equivalent to ceil(size / 64)
 */
#define SHA_INITIAL_CHUNKS(SIZE) (((SIZE) & 0b111111) ? ((SIZE) >> 6) + 1 : (SIZE) >> 6)

/*
 * Check if an extra chunk is needed
 *
 * Either if the message would occupy the 1-bit and the length bits
 *     or if the message already occupies a whole chunk
 */
#define SHA_EXTRA_CHUNK(SIZE) \
  ((((SIZE) & 0b111000) == 0b111000) || (((SIZE) & 0b111111) == 0b000000))

#define SHA_CHUNKS(SIZE) \
  (SHA_EXTRA_CHUNK(SIZE) ? (SHA_INITIAL_CHUNKS(SIZE) + 1) :  SHA_INITIAL_CHUNKS(SIZE))

#define SHA_ZEROS(SIZE, CHUNKS) (((CHUNKS) * 64 - (SIZE)) * 8 - 64 - 1)

/*
 * Create the message block needed to generate the SHA256 hash
 *
 * PARAMS
 * - uint32_t* block     | A pointer to the beginning of the block
 * - size_t chunks       | The amount of chunks in the block
 * - uint16_t zeros      | The amount of zeros between the message and the length
 * - const void* message | The message to hash
 * - size_t size         | The amount of bytes (8 bits)
 */
static inline void sha_block_create(uint32_t* block, size_t chunks, uint16_t zeros, const void* message, size_t size)
{
  // 1. Copy the encoded message to the message block
  sha_block_message_prepend(block, message, size);

  // 2. Append a single '1' to the encoded message
  SHA_BIT_SET(block, size * 8);

  // 3. Add zeros between the encoded message and the length integer
  for(size_t index = 0; index < zeros; index++)
  {
    SHA_BIT_OFF(block, size * 8 + 1 + index);
  }
  // 4. Copy binary representation of length to end of block
  // The length is the amount of bits (1 byte = 8 bits)
  uint64_t length = (uint64_t) size * 8;

  block[(chunks * 16) - 2] = (uint32_t) (length >> 32);
  block[(chunks * 16) - 1] = (uint32_t) length;
}

/*
 * Create a SHA256 hash of the inputted message block
 *
 * PARAMS
 * - char hash[64]         | A pointer to the "will be created"-hash
 * - const uint32_t* block | The block to hash 
 * - size_t chunks         | The amount of chunks (512 bits)
 *
 * RETURN (char* hash)
 */
static inline char* sha_block_hash(char hash[64], const uint32_t* block, size_t chunks)
{
  // first 32 bits of the fractional parts of the square roots of the first 8 primes
  uint32_t hs[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
  };

  // Update the "h"-values with every chunk in the block
  for(size_t index = 0; index < chunks; index++)
  {
    // block + (index * 16) points to the current chunk
    sha_hs_chunk_update(hs, block + (index * 16));
  }

  return sha_hs_hash(hash, hs); 
}

/*
 * Create a SHA256 hash of the inputted message
 *
 * The created hash is not null terminated
 *
 * PARAMS
 * - char hash[64]       | A pointer to the "will be created"-hash 
 * - const void* message | The message to hash
 * - size_t size         | The amount of bytes (8 bits)
 *
 * RETURN (char* hash)
 */
char* sha256(char hash[64], const void* message, size_t size)
{
  size_t   chunks = SHA_CHUNKS(size);
  uint16_t zeros  = SHA_ZEROS (size, chunks);

  uint32_t* block = malloc(sizeof(uint32_t) * chunks * 16);

  sha_block_create(block, chunks, zeros, message, size);

  hash = sha_block_hash(hash, block, chunks);

  free(block);

  return hash;
}

#endif // SHA256_IMPLEMENT
