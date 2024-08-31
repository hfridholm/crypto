/*
 * crypto - cryptography utillity
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-08-31
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <argp.h>

#include "aes.h"
#include "file.h"

static char doc[] = "crypto - cryptography utillity";

static char args_doc[] = "[INPUT] [OUTPUT]";

static struct argp_option options[] =
{
  { "cipher",  'c', "STRING", 0, "Encryption function" },
  { "key",     'k', "FILE",   0, "Encryption key file" },
  { "encrypt", 'e', 0,        0, "Encrypt message" },
  { "decrypt", 'd', 0,        0, "Decrypt message" },
  { 0 }
};

struct args
{
  char* args[2];
  char* cipher;
  char* key_file;
  bool  encrypt;
};

struct args args =
{
  .cipher    = "aes256",
  .key_file  = NULL,
  .encrypt   = true
};

/*
 * This is the option parsing function used by argp
 */
static error_t opt_parse(int key, char* arg, struct argp_state* state)
{
  struct args* args = state->input;

  switch(key)
  {
    case 'c':
      args->cipher = arg;
      break;

    case 'k':
      args->key_file = arg;
      break;

    case 'd':
      args->encrypt = false;
      break;

    case 'e':
      args->encrypt = true;
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
static void aes_encrypt_handler(const char* message, size_t size, const char* key, size_t key_size)
{
  char result[size + 16 - (size % 16)];
  memset(result, '\0', sizeof(result));
  
  aes_encrypt(result, message, size, key, key_size);

  file_write(result, sizeof(result), 1, args.args[1]);
}

/*
 *
 */
static void aes_decrypt_handler(const char* message, size_t size, const char* key, size_t key_size)
{
  char result[size];
  memset(result, '\0', sizeof(result));
  
  aes_decrypt(result, message, size, key, key_size);
  
  file_write(result, sizeof(result), 1, args.args[1]);
}

/*
 * RETURN (int status)
 * - 0 | Success!
 * - 1 | No key was inputted
 */
static int key_input(char* key, size_t size)
{
  char buffer[1024];
  memset(buffer, '\0', sizeof(buffer));

  printf("Key: ");

  if(fgets(buffer, sizeof(buffer), stdin) == NULL)
  {
    printf("No key was inputted\n");

    return 1;
  }

  memcpy(key, buffer, size);

  return 0;
}

/*
 *
 */
static void key_get(char* key, size_t size)
{
  if(args.key_file) file_read(key, size, 1, args.key_file);

  else key_input(key, size);
}

/*
 * RETURN (int status)
 * - 0 | Success!
 * - 1 | No key was inputted
 */
static int aes128_handler(const char* message, size_t size)
{
  size_t key_size = (args.key_file) ? file_size(args.key_file) : 16;

  char key[key_size + 1];
  memset(key, '\0', sizeof(key));

  key_get(key, key_size);

  if(args.encrypt) aes_encrypt_handler(message, size, key, AES_128);

  else             aes_decrypt_handler(message, size, key, AES_128);

  return 0; // Success!
}

/*
 * RETURN (int status)
 * - 0 | Success!
 * - 1 | No key was inputted
 */
static int aes192_handler(const char* message, size_t size)
{
  size_t key_size = (args.key_file) ? file_size(args.key_file) : 24;

  char key[key_size + 1];
  memset(key, '\0', sizeof(key));

  key_get(key, key_size);

  if(args.encrypt) aes_encrypt_handler(message, size, key, AES_192);

  else             aes_decrypt_handler(message, size, key, AES_192);

  return 0; // Success!
}

/*
 * RETURN (int status)
 * - 0 | Success!
 * - 1 | No key was inputted
 */
static int aes256_handler(const char* message, size_t size)
{
  size_t key_size = (args.key_file) ? file_size(args.key_file) : 32;

  char key[key_size + 1];
  memset(key, '\0', sizeof(key));

  key_get(key, key_size);

  if(args.encrypt) aes_encrypt_handler(message, size, key, AES_256);

  else             aes_decrypt_handler(message, size, key, AES_256);

  return 0; // Success!
}

static struct argp argp = { options, opt_parse, args_doc, doc };

/*
 * RETURNS
 * - 0 | Success!
 * - 1 | Failed to parse arguments
 * - 2 | Supplied input file is empty
 */
int main(int argc, char* argv[])
{
  argp_parse(&argp, argc, argv, 0, 0, &args);

  size_t size = file_size(args.args[0]);
  if(size == 0) return 2;

  char message[size + 1];
  memset(message, '\0', sizeof(message));

  file_read(message, size, 1, args.args[0]);

  if(!strcmp(args.cipher, "aes256"))
  {
    aes256_handler(message, size);
  }
  else if(!strcmp(args.cipher, "aes128"))
  {
    aes128_handler(message, size);
  }
  else if(!strcmp(args.cipher, "aes192"))
  {
    aes192_handler(message, size);
  }
  else if(!strcmp(args.cipher, "rsa"))
  {

  }
  else printf("Supplied cipher not supported.\n");

  return 0; // Success!
}
