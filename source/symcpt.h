#ifndef SYMCPT_H
#define SYMCPT_H

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <argp.h>

#include "aes.h"
#include "file.h"

extern char* sha256(char hash[64], const void* message, size_t size);

#endif // SYMCPT_H
