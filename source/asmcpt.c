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
 *
 */
static void encrypt_handler(const void* message, size_t size, pkey_t* pkey)
{
  // Get the password for the aes ecryption/decryption
  char aes_key[32];

  aes_key_generate(aes_key);

  printf("KEY: ");
  for(int index = 0; index < 32; index++)
  {
    printf("%x", aes_key[index] & 0xFF);
  }
  printf("\n");

  char encrypt[ENCRYPT_SIZE];
  memset(encrypt, '\0', sizeof(encrypt));

  rsa_encrypt(encrypt, aes_key, 32, pkey);
  
  printf("RSA: ");
  for(int index = 0; index < ENCRYPT_SIZE; index++)
  {
    printf("%x", encrypt[index] & 0xFF);
  }
  printf("\n");

  size_t aes_encrypt_size = (size + 15) & ~15;


  char* buffer = malloc(sizeof(char) * (aes_encrypt_size + ENCRYPT_SIZE));

  // 1. First comes the RSA encrypted AES key
  memcpy(buffer, encrypt, ENCRYPT_SIZE);

  // 2. Then comes the AES encrypted payload
  aes_encrypt(buffer + ENCRYPT_SIZE, message, size, aes_key, AES_256);

  file_write(buffer, aes_encrypt_size + ENCRYPT_SIZE, args.args[1]);

  free(buffer);
}

/*
 *
 */
static void decrypt_handler(const void* message, size_t size, skey_t* skey)
{
  printf("ENCRYPT_SIZE: %d\n", ENCRYPT_SIZE);
  printf("MESSAGE_SIZE: %d\n", MESSAGE_SIZE);
  printf("size: %ld\n", size);

  printf("RSA: ");
  for(int index = 0; index < ENCRYPT_SIZE; index++)
  {
    printf("%x", ((char*)message)[index] & 0xFF);
  }
  printf("\n");

  char aes_key[MESSAGE_SIZE];
  memset(aes_key, '\0', sizeof(aes_key));

  // 1. First comes the RSA encrypted AES key
  rsa_decrypt(aes_key, message, ENCRYPT_SIZE, skey);

  printf("KEY: ");
  for(int index = 0; index < MESSAGE_SIZE; index++)
  {
    printf("%x", aes_key[index] & 0xFF);
  }
  printf("\n");

  char* result = malloc(sizeof(char) * (size - ENCRYPT_SIZE));
  memset(result, '\0', (size - ENCRYPT_SIZE));

  // 2. Then comes the AES encrypted payload
  aes_decrypt(result, message + ENCRYPT_SIZE, (size - ENCRYPT_SIZE), aes_key, AES_256);

  file_write(result, (size - ENCRYPT_SIZE), args.args[1]);

  free(result);
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

  if(args.encrypt)
  {
    encrypt_handler(message, size, &pkey);
  }
  else
  {
    decrypt_handler(message, size, &skey);
  }

  free(message);

  keys_free(&skey, &pkey);

  return 0;
}
