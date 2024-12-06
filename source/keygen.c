/*
 * keygen.c
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-11-21
 */

#include "keygen.h"

#define SKEY_FILE "skey"
#define PKEY_FILE "pkey"

#define KEY_DIR "."


static char doc[] = "keygen - asymetric key generation utillity";

static char args_doc[] = "";

static struct argp_option options[] =
{
  { "dir",    'd', "DIR",   0, "Key directory" },
  { "bytes",  'b', "COUNT", 0, "Key modulus size" },
  { "force",  'f', 0,       0, "Overwrite dir keys" },
  { "quiet",  'q', 0,       0, "Don't produce any output" },
  { "silent", 's', 0,       OPTION_ALIAS },
  { "debug",  'x', 0,       0, "Output debug messages" },
  { 0 }
};

struct args
{
  char*  dir;
  size_t bytes;
  bool   force;
  bool   quiet;
  bool   debug;
};

struct args args =
{
  .dir   = KEY_DIR,
  .bytes = 0,
  .force = false,
  .quiet = false,
  .debug = false
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

    case 'q': case 's':
      if(args->debug) argp_usage(state);

      args->quiet = true;
      break;

    case 'x':
      if(args->quiet) argp_usage(state);

      args->debug = true;
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
static int skey_base64_encode(char** result, size_t* size, const skey_t* key)
{
  char* buffer;
  size_t buffer_size;

  if(skey_encode(&buffer, &buffer_size, key) != 0)
  {
    return 1;
  }

  if(base64_encode(result, size, buffer, buffer_size) != 0)
  {
    free(buffer);

    return 2;
  }

  free(buffer);

  return 0;
}

/*
 *
 */
static int pkey_base64_encode(char** result, size_t* size, const pkey_t* key)
{
  char* buffer;
  size_t buffer_size;

  if(pkey_encode(&buffer, &buffer_size, key) != 0)
  {
    return 1;
  }

  if(base64_encode(result, size, buffer, buffer_size) != 0)
  {
    free(buffer);

    return 2;
  }

  free(buffer);

  return 0;
}

/*
 *
 */
static int pkey_handler(pkey_t* key)
{
  char*  base64;
  size_t size;

  if(pkey_base64_encode(&base64, &size, key) != 0)
  {
    return 1;
  }

  if(dir_file_size_get(args.dir, PKEY_FILE) > 0 && !args.force)
  {
    return 2;
  }

  dir_file_write(base64, size, args.dir, PKEY_FILE);

  return 0;
}

/*
 *
 */
static int skey_handler(skey_t* key)
{
  char*  base64;
  size_t size;

  if(skey_base64_encode(&base64, &size, key) != 0)
  {
    return 1;
  }

  if(dir_file_size_get(args.dir, SKEY_FILE) > 0 && !args.force)
  {
    return 2;
  }

  dir_file_write(base64, size, args.dir, SKEY_FILE);

  return 0;
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

  if(args.debug)
    info_print("Start of main");

  skey_t skey;
  pkey_t pkey;

  keys_generate(&skey, &pkey);


  if(pkey_handler(&pkey) != 0)
  {
    if(!args.quiet)
      fprintf(stderr, "keygen : Failed to write public key\n");
  }

  if(skey_handler(&skey) != 0)
  {
    if(!args.quiet)
      fprintf(stderr, "keygen : Failed to write secret key\n");
  }

  keys_free(&skey, &pkey);

  if(args.debug)
    info_print("End of main");

  return 0;
}
