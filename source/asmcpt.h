/*
 * asmcpt - asymetric cryptography utillity
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-11-21
 */

#ifndef ASMCPT_H
#define ASMCPT_H

#include "file.h"
#include "rsa.h"
#include "aes.h"

#include <stdbool.h>
#include <argp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

extern size_t base64_encode(void* result, const void* message, size_t size);

extern size_t base64_decode(void* result, const void* message, size_t size);

#endif // ASMCPT_H
