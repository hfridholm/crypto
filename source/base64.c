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

static const char charset[64] =
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
 * Encode a message using base64
 */
int base64_encode(void* result, const void* message, size_t size)
{
  for(size_t index = 0; index + 3 <= size; index += 3)
  {

  }

  return 0;
}

/*
 * Decode a base64 message
 */
int base64_decode(void* result, const void* message, size_t size)
{
  return 0;
}
