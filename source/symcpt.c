/*
 * symcpt - symetric cryptography utillity
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-11-15
 */

#include "symcpt.h"

#define DEFAULT_CIPHER "aes256"

static char doc[] = "symcpt - symetric cryptography utillity";

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
  .cipher   = DEFAULT_CIPHER,
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
 * Symetric encrypt a message
 */
static int sym_encrypt(char** result, size_t* rsize, const void* message, size_t msize, const void* password, size_t psize, ksize_t key_size)
{
  if(!result || !message || !password) return 1;

  // 1. Hash the password to get aes key
  char hash[64];

  sha256(hash, password, psize);


  // 2. Concatonate the hash and the message to get payload
  size_t payload_size = (64 + msize);

  char* payload = malloc(sizeof(char) * payload_size);

  memcpy(payload, hash, 64);

  memcpy(payload + 64, message, msize);


  // 3. Encrypt the payload using AES and hash as key
  if(aes_encrypt(result, rsize, payload, payload_size, hash, key_size) != 0)
  {
    free(payload);

    fprintf(stderr, "symcpt: Error: aes_encrypt\n");

    return 2;
  }

  free(payload);

  return 0;
}

/*
 * Decrypted a symetric encrypted message
 */
static int sym_decrypt(char** result, size_t* rsize, const void* message, size_t msize, const void* password, size_t psize, ksize_t key_size)
{
  if(!result || !message || !password) return 1;

  // 1. Hash the password to get aes key
  char hash[64];

  sha256(hash, password, psize);
  
  // 2. Decrypt message to get payload
  char* payload;
  size_t payload_size;

  if(aes_decrypt(&payload, &payload_size, message, msize, hash, key_size) != 0)
  {
    fprintf(stderr, "symcpt: Error: aes_decrypt\n");

    return 2;
  }

  // 3. Compare the encrypted hash, to validate
  if(memcmp(payload, hash, 64) != 0)
  {
    fprintf(stderr, "symcpt: Invalid decryption\n");

    free(payload);

    return 3;
  }

  // 4. Allocate memory and store the result message
  size_t result_size = (payload_size - 64);

  if(rsize) *rsize = result_size;

  *result = malloc(sizeof(char) * result_size);

  memcpy(*result, payload + 64, result_size);

  free(payload);

  return 0;
}

/*
 *
 */
static int key_size_get(ksize_t* key_size)
{
  if(strcmp(args.cipher, "aes256") == 0)
  {
    *key_size = AES_256;

    return 1;
  }
  else if(strcmp(args.cipher, "aes192") == 0)
  {
    *key_size = AES_192;

    return 2;
  }
  else if(strcmp(args.cipher, "aes128") == 0)
  {
    *key_size = AES_128;

    return 3;
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

/*
 *
 */
static void encrypt_routine(const void* message, size_t msize, const void* password, size_t psize, ksize_t key_size)
{
  char* result;
  size_t rsize;

  if(sym_encrypt(&result, &rsize, message, msize, password, psize, key_size) == 0)
  {
    file_write(result, rsize, args.args[1]);

    free(result);
  }
}

/*
 *
 */
static void decrypt_routine(const void* message, size_t msize, const void* password, size_t psize, ksize_t key_size)
{
  char* result;
  size_t rsize;

  if(sym_decrypt(&result, &rsize, message, msize, password, psize, key_size) == 0)
  {
    file_write(result, rsize, args.args[1]);

    free(result);
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
    fprintf(stderr, "symcpt: Inputted file has no data\n");

    return 1;
  }

  // Read the file and store the data as the message
  char* message = malloc(sizeof(char) * size);

  if(file_read(message, size, args.args[0]) == 0)
  {
    fprintf(stderr, "symcpt: Failed to read file\n");

    return 2;
  }

  // Get the password for the aes ecryption/decryption
  char* password = password_get();


  // Get the AES key size
  ksize_t key_size;

  if(key_size_get(&key_size) == 0)
  {
    fprintf(stderr, "symcpt: Cipher not supported\n");

    return 3;
  }

  if(args.encrypt)
  {
    encrypt_routine(message, size, password, strlen(password), key_size);
  }
  else
  {
    decrypt_routine(message, size, password, strlen(password), key_size);
  }

  free(message);
  free(password);

  return 0;
}
