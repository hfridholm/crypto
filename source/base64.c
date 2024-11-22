/*
 * base64
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-11-17
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char symbols[64] =
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
static void map_encode(uint8_t buffer[4], const uint8_t tmp[3])
{
  buffer[0] = ( tmp[0] & 0xfc) >> 2;
  buffer[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
  buffer[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
  buffer[3] =   tmp[2] & 0x3f;
}

/*
 *
 */
static void symbols_encode(void* result, size_t r_index, uint8_t buffer[4], int bytes)
{
  for(int index = 0; index < bytes; index++)
  {
    char symbol = symbols[buffer[index]];

    ((char*) result)[r_index + index] = symbol;
  }

  for(int index = bytes; index < 4; index++)
  {
    ((char*) result)[r_index + index] = '=';
  }
}

/*
 * Encode a message using base64
 *
 * RETURN (size_t size)
 * - The size of the result
 */
size_t base64_encode(void* result, const void* message, size_t size)
{
  if(!result || !message) return 0;

  size_t m_index, r_index = 0;

  uint8_t tmp[3];
  uint8_t buffer[4];

  // 1. Encode the main part of the message
  for(m_index = 0; m_index + 3 <= size; m_index += 3)
  {
    memcpy(tmp, message + m_index, 3);

    map_encode(buffer, tmp);

    symbols_encode(result, r_index, buffer, 4);

    r_index += 4;
  }

  // 2. Encode the rest of the message
  if(size > m_index)
  {
    memset(tmp, 0, 3);

    memcpy(tmp, message, size - m_index);

    map_encode(buffer, tmp);

    size_t bytes = (size - m_index) + 1;

    symbols_encode(result, r_index, buffer, bytes);

    r_index += 4;
  }

  return r_index;
}

/*
 *
 */
static int symbol_index_get(char symbol)
{
  for (int i = 0; i < 64; i++)
  {
    if (symbols[i] == symbol)
    {
      return i;
    }
  }

  return 0;
}

/*
 *
 */
static void map_decode(uint8_t buffer[3], uint8_t tmp[4])
{
  buffer[0] =  (tmp[0] << 2) +        ((tmp[1] & 0x30) >> 4);
  buffer[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
  buffer[2] = ((tmp[2] & 0x3) << 6) +   tmp[3];
}

/*
 * The function returns the amount of bytes decoded
 *
 * RETURN (int bytes)
 */
static int symbols_decode(uint8_t tmp[4], const void* message, size_t m_index)
{
  int bytes;

  for(bytes = 0; bytes < 4; bytes++)
  {
    char symbol = ((char*) message)[m_index + bytes];

    if(symbol == '=') return bytes;

    tmp[bytes] = symbol_index_get(symbol);
  }

  return bytes;
}

/*
 * Decode a base64 message
 *
 * RETURN (size_t size)
 * - The size of the result
 */
size_t base64_decode(void* result, const void* message, size_t size)
{
  if(!result || !message) return 0;

  size_t m_index, r_index = 0;

  uint8_t tmp[4];
  uint8_t buffer[3];

  for(m_index = 0; m_index + 4 <= size; m_index += 4)
  {
    int bytes = symbols_decode(tmp, message, m_index);

    map_decode(buffer, tmp);

    memcpy(result + r_index, buffer, bytes - 1);

    r_index += bytes - 1;
  }

  return r_index;
}
