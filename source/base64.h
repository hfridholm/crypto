/*
 * base64.h - implementation of base64 encoder
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-12-06
 *
 *
 * In main compilation unit; define BASE64_IMPLEMENT
 *
 *
 * These are the available functions:
 *
 * int base64_encode(char** result, size_t* rsize, const void* message, size_t msize)
 *
 * int base64_decode(char** result, size_t* rsize, const void* message, size_t msize)
 */

/*
 * From here on, until BASE64_IMPLEMENT,
 * it is like a normal header file with declarations
 */

#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>

extern int base64_encode(char** result, size_t* rsize, const void* message, size_t msize);

extern int base64_decode(char** result, size_t* rsize, const void* message, size_t msize);

#endif // BASE64_H

/*
 * This header library file uses _IMPLEMENT guards
 *
 * If BASE64_IMPLEMENT is defined, the definitions will be included
 */

#ifdef BASE64_IMPLEMENT

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * These are the symbols of base 64
 */
static const char B64_SYMBOLS[64] =
{
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/',
};

/*
 * Map 3 8-bit chunks into 4 6-bit chunks
 */
static inline void b64_map_encode(uint8_t buffer[4], const uint8_t tmp[3])
{
  buffer[0] = ( tmp[0] & 0xfc) >> 2;
  buffer[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
  buffer[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
  buffer[3] =   tmp[2] & 0x3f;
}

/*
 * Encode the mapped numbers to symbols of base 64
 */
static inline void b64_symbols_encode(void* result, size_t r_index, uint8_t buffer[4], int bytes)
{
  // 1. Encode the mapped numbers
  for(int index = 0; index < bytes; index++)
  {
    char symbol = B64_SYMBOLS[buffer[index]];

    ((char*) result)[r_index + index] = symbol;
  }

  // 2. Add padding if not all 4 bytes were encoded
  for(int index = bytes; index < 4; index++)
  {
    ((char*) result)[r_index + index] = '=';
  }
}

/*
 * Encode a message using base64
 *
 * RETURN (int status)
 * - 0 | Success
 * - 1 | Bad input
 * - 2 | Failed to malloc memory
 */
int base64_encode(char** result, size_t* rsize, const void* message, size_t msize)
{
  if(!result || !message) return 1;

  // 1. Allocate memory to result
  size_t result_size = ((msize * 4 / 3) + 3) & ~3;

  *result = malloc(sizeof(char) * result_size);

  if(!(*result)) return 2;


  size_t m_index, r_index = 0;

  uint8_t tmp[3];    // 3 8-bit chunks of data
  uint8_t buffer[4]; // 4 6-bit chunks of base 64 symbols

  // 1. Encode the main part of the message
  for(m_index = 0; m_index + 3 <= msize; m_index += 3)
  {
    memcpy(tmp, message + m_index, 3);

    b64_map_encode(buffer, tmp);

    b64_symbols_encode(*result, r_index, buffer, 4);

    r_index += 4;
  }

  // 2. Encode the rest of the message
  if(msize > m_index)
  {
    memset(tmp, 0, 3);

    memcpy(tmp, message, msize - m_index);

    b64_map_encode(buffer, tmp);

    size_t bytes = (msize - m_index) + 1;

    b64_symbols_encode(*result, r_index, buffer, bytes);

    r_index += 4;
  }

  if(rsize) *rsize = r_index;

  return 0;
}

/*
 * Get the index of a symbol in base 64
 *
 * RETURN (int index)
 * - >= 0 | Index of symbol
 * -   -1 | Symbol does not exist
 */
static inline int b64_symbol_index_get(char symbol)
{
  for(int index = 0; index < 64; index++)
  {
    if (B64_SYMBOLS[index] == symbol) return index;
  }

  return -1;
}

/*
 * Map 4 8-bit chunks into 3 8-bit chunks
 */
static inline void b64_map_decode(uint8_t buffer[3], uint8_t tmp[4])
{
  buffer[0] =  (tmp[0] << 2) +        ((tmp[1] & 0x30) >> 4);
  buffer[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
  buffer[2] = ((tmp[2] & 0x3) << 6) +   tmp[3];
}

/*
 * The function returns the amount of bytes decoded
 *
 * RETURN (int bytes)
 * - -1 | Invalid symbol
 */
static inline int b64_symbols_decode(uint8_t tmp[4], const void* message, size_t m_index)
{
  int bytes;

  for(bytes = 0; bytes < 4; bytes++)
  {
    char symbol = ((char*) message)[m_index + bytes];

    if(symbol == '=') return bytes;

    int index = b64_symbol_index_get(symbol);

    if(index == -1) return -1;

    tmp[bytes] = index;
  }

  return bytes;
}

/*
 * Decode a base64 message
 *
 * RETURN (int status)
 * - 0 | Success
 * - 1 | Bad input
 * - 2 | Failed to malloc memory
 */
int base64_decode(char** result, size_t* rsize, const void* message, size_t msize)
{
  if(!result || !message) return 1;

  // 1. Allocate memory to result
  size_t result_size = (msize * 3 / 4);

  *result = malloc(sizeof(char) * result_size);

  if(!(*result)) return 2;


  size_t m_index, r_index = 0;

  uint8_t tmp[4];    // 4 6-bit chunks of base 64 symbols
  uint8_t buffer[3]; // 3 8-bit chunks of data

  // 2. Decode the message
  for(m_index = 0; m_index + 4 <= msize; m_index += 4)
  {
    int bytes = b64_symbols_decode(tmp, message, m_index);

    // Handle error better in the future:
    if(bytes == -1) break;

    b64_map_decode(buffer, tmp);

    memcpy(*result + r_index, buffer, bytes - 1);

    r_index += bytes - 1;
  }

  if(rsize) *rsize = r_index;

  return 0;
}

#endif // BASE64_IMPLEMENT
