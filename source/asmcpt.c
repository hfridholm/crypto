/*
 * asmcpt - asymetric cryptography utillity
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-11-21
 */

#include "asmcpt.h"

static char doc[] = "asmcpt - asymetric cryptography utillity";

static char args_doc[] = "[INPUT] [OUTPUT]";

static struct argp_option options[] =
{
  { "secret",   's', "STRING", 0, "Secret key file" },
  { "public",   'p', "STRING", 0, "Public key file" },
  { "encrypt",  'e', 0,        0, "Encrypt file" },
  { "decrypt",  'd', 0,        0, "Decrypt file" },
  { 0 }
};

struct args
{
  char* args[2];
  char* secret;
  char* public;
  bool  encrypt;
};

struct args args =
{
  .secret  = NULL,
  .public  = NULL,
  .encrypt = true
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
static void base64_skey_decode(skey_t* key, const void* message, size_t size)
{
  char buffer[size];

  size_t buffer_size = base64_decode(buffer, message, size);

  skey_decode(key, buffer, buffer_size);
}

/*
 *
 */
static void base64_pkey_decode(pkey_t* key, const void* message, size_t size)
{
  char buffer[size];

  size_t buffer_size = base64_decode(buffer, message, size);

  pkey_decode(key, buffer, buffer_size);
}

/*
 *
 */
static void pkey_handler(pkey_t* key)
{
  size_t file_size = file_size_get("pkey");

  char base64[file_size];

  file_read(base64, file_size, "pkey");

  base64_pkey_decode(key, base64, file_size);
}

/*
 *
 */
static void skey_handler(skey_t* key)
{
  size_t file_size = file_size_get("skey");

  char base64[file_size];

  file_read(base64, file_size, "skey");

  base64_skey_decode(key, base64, file_size);
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
static int asm_encrypt(char** result, size_t* rsize, const void* message, size_t size, pkey_t* pkey)
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
  size_t aes_message_size = (size + 15) & ~15;

  char* aes_message = malloc(sizeof(char) * aes_message_size);

  aes_encrypt(aes_message, NULL, message, size, aes_key, AES_256);


  // 4. Concatonate the different variables to a result
  *rsize = (1 + rsa_size + aes_message_size);

  *result = malloc(sizeof(char) * *rsize);

  // 1. First comes the RSA encrypted size
  *result[0] = (char) rsa_size;

  // 2. Then comes the RSA encrypted AES key
  memcpy(*result + 1, aes_key_enc, rsa_size);

  // 3. Then comes the AES encrypted message
  memcpy(*result + 1 + rsa_size, aes_message, aes_message_size);

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
static int asm_decrypt(char** result, size_t* rsize, const void* message, size_t size, skey_t* skey)
{
  if(!result || !message || !skey) return 1;

  // 1. Get the size of the RSA encryption
  size_t rsa_size = (size_t) *((char*) message);


  // 2. Then comes the RSA encrypted AES key
  char aes_key[ENCRYPT_SIZE]; // Eigentlich MESSAGE_SIZE

  memset(aes_key, '\0', sizeof(aes_key));

  rsa_decrypt(aes_key, NULL, message + 1, rsa_size, skey);


  // 3. Then comes the AES encrypted message
  size_t aes_message_size = (size - 1 - rsa_size);

  *result = malloc(sizeof(char) * aes_message_size);

  aes_decrypt(*result, rsize, message + 1 + rsa_size, aes_message_size, aes_key, AES_256);

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

  skey_t skey;
  pkey_t pkey;

  skey_handler(&skey);

  pkey_handler(&pkey);

  // Get the size of the inputted file
  // If the size is 0 (no data), the file is of no use
  size_t size = file_size_get(args.args[0]);

  if(size == 0)
  {
    fprintf(stderr, "asmcpt: Inputted file has no data\n");
  
    keys_free(&skey, &pkey);

    return 1;
  }

  // Read the file and store the data as the message
  char* message = malloc(sizeof(char) * size);

  if(file_read(message, size, args.args[0]) == 0)
  {
    fprintf(stderr, "asmcpt: Failed to read file\n");

    keys_free(&skey, &pkey);

    return 2;
  }

  char* result;
  size_t rsize;

  if(args.encrypt)
  {
    if(asm_encrypt(&result, &rsize, message, size, &pkey) == 0)
    {
      file_write(result, rsize, args.args[1]);

      free(result);
    }
  }
  else
  {
    if(asm_decrypt(&result, &rsize, message, size, &skey) == 0)
    {
      file_write(result, rsize, args.args[1]);

      free(result);
    }
  }

  free(message);

  keys_free(&skey, &pkey);

  return 0;
}
