/*
 * asmcpt - asymetric cryptography utillity
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-11-21
 */

#include "rsa.h"

#define AES_IMPLEMENT
#include "aes.h"

#define BASE64_IMPLEMENT
#include "base64.h"

#define FILE_IMPLEMENT
#include "file.h"

#define DEBUG_IMPLEMENT
#include "debug.h"

#include <stdbool.h>
#include <argp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>


#define SKEY_FILE "skey"
#define PKEY_FILE "pkey"

#define KEY_DIR "."


static char doc[] = "asmcpt - asymetric cryptography utillity";

static char args_doc[] = "[INPUT] [OUTPUT]";

static struct argp_option options[] =
{
  { "secret",  's', "FILE", 0, "Secret key file" },
  { "public",  'p', "FILE", 0, "Public key file" },
  { "dir",     'D', "DIR",  0, "Key directory" },
  { "encrypt", 'e', 0,      0, "Encrypt file" },
  { "decrypt", 'd', 0,      0, "Decrypt file" },
  { "quiet",   'q', 0,      0, "Don't produce any output" },
  { "debug",   'x', 0,      0, "Output debug messages" },
  { 0 }
};

struct args
{
  char* args[2];
  char* secret;
  char* public;
  char* dir;
  bool  encrypt;
  bool  quiet;
  bool  debug;
};

struct args args =
{
  .secret  = SKEY_FILE,
  .public  = PKEY_FILE,
  .dir     = KEY_DIR,
  .encrypt = true,
  .quiet   = false,
  .debug   = false
};

/*
 * This is the option parsing function used by argp
 */
static error_t opt_parse(int key, char* arg, struct argp_state* state)
{
  struct args* args = state->input;

  switch(key)
  {
    case 's':
      args->secret = arg;
      break;

    case 'p':
      args->public = arg;
      break;

    case 'd':
      args->encrypt = false;
      break;

    case 'e':
      args->encrypt = true;
      break;

    case 'D':
      args->dir = arg;
      break;

    case 'q':
      if(args->debug) argp_usage(state);

      args->quiet = true;
      break;

    case 'x':
      if(args->quiet) argp_usage(state);

      args->debug = true;
      break;

    case ARGP_KEY_ARG:
      if(state->arg_num >= 2) argp_usage(state);

      args->args[state->arg_num] = arg;
      break;

    case ARGP_KEY_END:
      if(state->arg_num < 2) argp_usage(state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

/*
 *
 */
static int base64_skey_decode(skey_t* key, const void* message, size_t size)
{
  char*  buffer;
  size_t buffer_size;

  if(base64_decode(&buffer, &buffer_size, message, size) != 0)
  {
    return 1;
  }

  if(skey_decode(key, buffer, buffer_size) != 0)
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
static int base64_pkey_decode(pkey_t* key, const void* message, size_t size)
{
  char*  buffer;
  size_t buffer_size;

  if(base64_decode(&buffer, &buffer_size, message, size) != 0)
  {
    return 1;
  }

  if(pkey_decode(key, buffer, buffer_size) != 0)
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
static int pkey_get(pkey_t* key)
{
  size_t file_size = dir_file_size_get(args.dir, args.public);

  char base64[file_size];

  if(dir_file_read(base64, file_size, args.dir, args.public) == 0)
  {
    if(!args.quiet)
      fprintf(stderr, "asmcpt: Failed to read file\n");

    return 1;
  }

  if(base64_pkey_decode(key, base64, file_size) != 0)
  {
    if(!args.quiet)
      fprintf(stderr, "asmcpt: Failed to decode base64\n");

    return 2;
  }

  return 0;
}

/*
 *
 */
static int skey_get(skey_t* key)
{
  size_t file_size = dir_file_size_get(args.dir, args.secret);

  char base64[file_size];

  if(dir_file_read(base64, file_size, args.dir, args.secret) == 0)
  {
    return 1;
  }

  if(base64_skey_decode(key, base64, file_size) != 0)
  {
    return 2;
  }

  return 0;
}

/*
 * Generate random bytes as the key used for encryption
 */
static void aes_key_generate(char buffer[32])
{
  for(size_t index = 0; index < 32; index++)
  {
    buffer[index] = rand() % 0xFF; 
  }
}

/*
 * Asymetric encrypt the message
 *
 * This function allocates rsize bytes memory to result
 *
 * RETURN (int status)
 * - 0 | Success
 * - 1 | Supplied arguments invalid
 */
static int asm_encrypt(char** result, size_t* rsize, const void* message, size_t msize, pkey_t* pkey)
{
  if(!result || !message || !pkey) return 1;

  // 1. Generate AES key
  char aes_key[32];

  aes_key_generate(aes_key);

  // 2. Encrypt the AES key using RSA
  char aes_key_enc[ENCRYPT_SIZE];

  size_t rsa_size;

  rsa_encrypt(aes_key_enc, &rsa_size, aes_key, 32, pkey);


  // 3. Encrypt the message using the AES key
  size_t aes_size;
  char* aes_message;

  if(aes_encrypt(&aes_message, &aes_size, message, msize, aes_key, AES_256) != 0)
  {
    return 2;
  }


  // 4. Concatonate the different variables to a result
  size_t result_size = (1 + rsa_size + aes_size);

  if(rsize) *rsize = result_size;

  *result = malloc(sizeof(char) * result_size);

  // 1. First comes the RSA encrypted size
  *result[0] = (char) rsa_size;

  // 2. Then comes the RSA encrypted AES key
  memcpy(*result + 1, aes_key_enc, rsa_size);

  // 3. Then comes the AES encrypted message
  memcpy(*result + 1 + rsa_size, aes_message, aes_size);

  free(aes_message);

  return 0;
}

/*
 * Decrypt the asymetric encrypted message
 *
 * This function allocates rsize bytes memory to result
 *
 * RETURN (int status)
 * - 0 | Success
 * - 1 | Supplied arguments invalid
 */
static int asm_decrypt(char** result, size_t* rsize, const void* message, size_t msize, skey_t* skey)
{
  if(!result || !message || !skey) return 1;

  // Check if the message is large enough
  if(msize < (1 + ENCRYPT_SIZE + AES_SIZE(1)))
  {
    if(!args.quiet)
      fprintf(stderr, "asmcpt: File is to small\n");

    return 2;
  }

  // 1. Get the size of the RSA encryption
  size_t rsa_size = (size_t) *((char*) message);


  // 2. Then comes the RSA encrypted AES key
  char aes_key[ENCRYPT_SIZE]; // Eigentlich MESSAGE_SIZE

  memset(aes_key, '\0', sizeof(aes_key));

  rsa_decrypt(aes_key, NULL, message + 1, rsa_size, skey);


  // 3. Then comes the AES encrypted message
  size_t aes_size = (msize - 1 - rsa_size);

  if(aes_decrypt(result, rsize, message + 1 + rsa_size, aes_size, aes_key, AES_256) != 0)
  {
    return 2;
  }

  return 0;
}

/*
 *
 */
static void encrypt_routine(const void* message, size_t size)
{
  pkey_t pkey;

  if(pkey_get(&pkey) != 0)
  {
    if(!args.quiet)
      fprintf(stderr, "asmcpt: Failed to get public key\n");

    return;
  }

  char* result;
  size_t rsize;

  if(asm_encrypt(&result, &rsize, message, size, &pkey) == 0)
  {
    file_write(result, rsize, args.args[1]);

    free(result);
  }

  pkey_free(&pkey);
}

/*
 *
 */
static void decrypt_routine(const void* message, size_t size)
{
  skey_t skey;

  if(skey_get(&skey) != 0)
  {
    if(!args.quiet)
      fprintf(stderr, "asmcpt: Failed to get secret key\n");

    return;
  }

  char* result;
  size_t rsize;

  if(asm_decrypt(&result, &rsize, message, size, &skey) == 0)
  {
    file_write(result, rsize, args.args[1]);

    free(result);
  }

  skey_free(&skey);
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

  /*
  printf("skey: %s/%s\n", args.dir, args.secret);
  printf("pkey: %s/%s\n", args.dir, args.public);
  */

  // Get the size of the inputted file
  // If the size is 0 (no data), the file is of no use
  size_t size = file_size_get(args.args[0]);

  if(size == 0)
  {
    if(!args.quiet)
      fprintf(stderr, "asmcpt: Inputted file has no data\n");
  
    return 1;
  }

  // Read the file and store the data as the message
  char* message = malloc(sizeof(char) * size);

  if(file_read(message, size, args.args[0]) == 0)
  {
    if(!args.quiet)
      fprintf(stderr, "asmcpt: Failed to read file\n");

    return 2;
  }

  if(args.encrypt) 
  {
    encrypt_routine(message, size);
  }
  else
  {
    decrypt_routine(message, size);
  }

  free(message);

  if(args.debug)
    info_print("End of main");

  return 0;
}
