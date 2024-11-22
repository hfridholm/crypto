/*
 * keygen.h
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-11-21
 */

#ifndef KEYGEN_H
#define KEYGEN_H

#include "file.h"
#include "rsa.h"
#include "aes.h"
#include "debug.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <argp.h>

extern size_t base64_encode(void* result, const void* message, size_t size);

extern size_t base64_decode(void* result, const void* message, size_t size);

#endif // KEYGEN_H
