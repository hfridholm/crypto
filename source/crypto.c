/*
 * crypto - cryptography utillity
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-11-15
 */

#include "crypto.h"

static char doc[] = "crypto - cryptography utillity";

static char args_doc[] = "[INPUT] [OUTPUT]";

static struct argp_option options[] =
{
  { "cipher",   'c', "STRING", 0, "AES cipher" },
  { "password", 'p', "STRING", 0, "Encryption password" },
  { "encrypt",  'e', 0,        0, "Encrypt file" },
  { "decrypt",  'd', 0,        0, "Decrypt file" },
  { 0 }
};

struct args
{
  char* args[2];
  char* cipher;
  char* password;
  bool  encrypt;
};

struct args args =
{
  .cipher   = "aes256",
  .password = NULL,
  .encrypt  = true
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

    case 'p':
      args->password = arg;
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
 * This function encrypts the message with the supplied key,
 * and writes the output to the output file
 *
 * The result has to be divisable by 16, larger than size if needed
 *
 * (size + 15) & ~15
 *
 * This statement produces the next number divisable by 16
 */
static void aes_encrypt_handler(const char* message, size_t size, const char* key, ksize_t key_size)
{
  size_t result_size = (size + 15) & ~15;

  char* result = malloc(sizeof(char) * result_size);
  
  aes_encrypt(result, message, size, key, key_size);

  file_write(result, result_size, args.args[1]);

  free(result);
}

/*
 * This function decrypts the message with the supplied key,
 * and writes the output to the output file
 */
static void aes_decrypt_handler(const char* message, size_t size, const char* key, ksize_t key_size)
{
  if(!(size & ~15)) return;

  char* result = malloc(sizeof(char) * size);
  
  aes_decrypt(result, message, size, key, key_size);
  
  file_write(result, size, args.args[1]);

  free(result);
}

/*
 * This function either encrypts or decrypts the message,
 * using AES 128 with the supplied password
 */
static void aes128_handler(const char* message, size_t size, const char* password)
{
  char key[16], hash[64];

  sha256(hash, password, strlen(password));

  memcpy(key, hash, sizeof(char) * 16);

  if(args.encrypt) aes_encrypt_handler(message, size, key, AES_128);

  else             aes_decrypt_handler(message, size, key, AES_128);
}

/*
 * This function either encrypts or decrypts the message,
 * using AES 192 with the supplied password
 */
static void aes192_handler(const char* message, size_t size, const char* password)
{
  char key[24], hash[64];

  sha256(hash, password, strlen(password));

  memcpy(key, hash, sizeof(char) * 24);

  if(args.encrypt) aes_encrypt_handler(message, size, key, AES_192);

  else             aes_decrypt_handler(message, size, key, AES_192);
}

/*
 * This function either encrypts or decrypts the message,
 * using AES 256 with the supplied password
 */
static void aes256_handler(const char* message, size_t size, const char* password)
{
  char key[32], hash[64];

  sha256(hash, password, strlen(password));

  memcpy(key, hash, sizeof(char) * 32);

  if(args.encrypt) aes_encrypt_handler(message, size, key, AES_256);

  else             aes_decrypt_handler(message, size, key, AES_256);
}

/*
 * This function either encrypts or decrypts the message,
 * using the supplied AES cipher with the supplied password
 *
 * RETURN (int status)
 * - 0       | Invalid cipher
 * - AES_256 | AES 256
 * - AES_192 | AES 192
 * - AES_128 | AES 128
 */
static int aes_handler(const char* message, size_t size, const char* password)
{
  if(strcmp(args.cipher, "aes256") == 0)
  {
    aes256_handler(message, size, password);

    return AES_256;
  }
  else if(strcmp(args.cipher, "aes192") == 0)
  {
    aes192_handler(message, size, password);

    return AES_192;
  }
  else if(strcmp(args.cipher, "aes128") == 0)
  {
    aes128_handler(message, size, password);

    return AES_128;
  }
  else return 0;
}

/*
 * Get the password needed for the aes action
 *
 * If a password has not been supplied from the command,
 * prompt the user to input a password
 *
 * RETURN (char* password)
 */
static char* password_get(void)
{
  if(args.password)
  {
    return strdup(args.password);
  }
  else
  {
    return getpass("Password: ");
  }
}

static struct argp argp = { options, opt_parse, args_doc, doc };

/*
 * RETURN (int status)
 * - 0 | Success
 * - 1 | Inputted file has no data
 * - 2 | Failed to read file
 * - 3 | Supplied cipher not supported
 */
int main(int argc, char* argv[])
{
  argp_parse(&argp, argc, argv, 0, 0, &args);

  // Get the size of the inputted file
  // If the size is 0 (no data), the file is of no use
  size_t size = file_size_get(args.args[0]);

  if(size == 0)
  {
    fprintf(stderr, "crypto: Inputted file has no data\n");

    return 1;
  }

  // Read the file and store the data as the message
  char* message = malloc(sizeof(char) * size);

  if(file_read(message, size, args.args[0]) == 0)
  {
    fprintf(stderr, "crypto: Failed to read file\n");

    return 2;
  }

  // Get the password for the aes ecryption/decryption
  char* password = password_get();

  // Perform aes encryption/decryption
  int status = aes_handler(message, size, password);

  free(message);
  free(password);

  // Check the status of the aes handler
  if(status == 0)
  {
    fprintf(stderr, "crypto: Supplied cipher not supported\n");

    return 3;
  }

  return 0;
}
