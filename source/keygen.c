/*
 * keygen.c
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-11-21
 */

#include "file.h"
#include "rsa.h"
#include "aes.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <argp.h>

extern size_t base64_encode(void* result, const void* message, size_t size);

extern size_t base64_decode(void* result, const void* message, size_t size);


static char* SKEY_FILE = "skey";
static char* PKEY_FILE = "pkey";

#define KEY_DIR "."


static char doc[] = "keygen - asymetric key generation utillity";

static char args_doc[] = "";

static struct argp_option options[] =
{
  { "directory", 'd', "STRING", 0, "Key directory" },
  { "bytes",     'b', "COUNT",  0, "Key modulus size" },
  { "force",     'f', 0,        0, "Overwrite dir keys" },
  { 0 }
};

struct args
{
  char*  dir;
  size_t bytes;
  bool   force;
};

struct args args =
{
  .dir   = KEY_DIR,
  .bytes = 0,
  .force = false
};

/*
 * This is the option parsing function used by argp
 */
static error_t opt_parse(int key, char* arg, struct argp_state* state)
{
  struct args* args = state->input;

  switch(key)
  {
    case 'd':
      args->dir = arg;
      break;

    case 'b':
      args->bytes = arg ? atoi(arg) : 0;
      break;

    case 'f':
      args->force = true;
      break;

    case ARGP_KEY_ARG:
      break;

    case ARGP_KEY_END:
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

/*
 *
 */
static size_t skey_base64_encode(void* result, const skey_t* key)
{
  char buffer[10000];
  memset(buffer, '\0', sizeof(buffer));

  size_t size = 0;

  skey_encode(buffer, &size, key);

  return base64_encode(result, &buffer, size);
}

/*
 *
 */
static size_t pkey_base64_encode(void* result, const pkey_t* key)
{
  char buffer[10000];
  memset(buffer, '\0', sizeof(buffer));

  size_t size = 0;

  pkey_encode(buffer, &size, key);

  return base64_encode(result, &buffer, size);
}

/*
 *
 */
static int pkey_handler(pkey_t* key)
{
  char buffer[10000];
  memset(buffer, '\0', sizeof(buffer));

  size_t size = pkey_base64_encode(buffer, key);

  if(args.force || dir_file_size_get(args.dir, PKEY_FILE) == 0)
  {
    dir_file_write(buffer, size, args.dir, PKEY_FILE);

    return 0;
  }
  else return 1;
}

/*
 *
 */
static int skey_handler(skey_t* key)
{
  char buffer[10000];
  memset(buffer, '\0', sizeof(buffer));

  size_t size = skey_base64_encode(buffer, key);

  if(args.force || dir_file_size_get(args.dir, SKEY_FILE) == 0)
  {
    dir_file_write(buffer, size, args.dir, SKEY_FILE);

    return 0;
  }
  else return 1;
}

static struct argp argp = { options, opt_parse, args_doc, doc };

/*
 * RETURN (int status)
 * - 0 | Success
 */
int main(int argc, char* argv[])
{
  argp_parse(&argp, argc, argv, 0, 0, &args);

  srand(time(NULL));

  skey_t skey;
  pkey_t pkey;

  keys_generate(&skey, &pkey);


  if(pkey_handler(&pkey) != 0)
  {
    printf("keygen : Failed to write public key\n");
  }

  if(skey_handler(&skey) != 0)
  {
    printf("keygen : Failed to write secret key\n");
  }

  keys_free(&skey, &pkey);

  return 0;
}
