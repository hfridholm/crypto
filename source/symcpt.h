#ifndef SYMCPT_H
#define SYMCPT_H

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <argp.h>

#define FILE_IMPLEMENT
#include "file.h"

#include "aes.h"

#define DEBUG_IMPLEMENT
#include "debug.h"

extern char* sha256(char hash[64], const void* message, size_t size);

#endif // SYMCPT_H
