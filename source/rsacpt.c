/*
 * Asymetric cryptition
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-11-18
 */

/*
 * -e file file.enc -p pkey
 *
 * -d file.enc file.dec -s skey
 */

#include "file.h"
#include "rsa.h"
#include "aes.h"

#include <stdbool.h>
#include <argp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

extern size_t base64_encode(void* result, const void* message, size_t size);

extern size_t base64_decode(void* result, const void* message, size_t size);


static char doc[] = "rsacpt - asymetric cryptography utillity";

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
 *
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

  // Perform aes encryption/decryption
  // aes_encrypt_handler(message, size, aes_key);


  char encrypt[1024];
  memset(encrypt, '\0', sizeof(encrypt));

  size_t enc_size = 0;

  rsa_encrypt(encrypt, &enc_size, aes_key, 32, pkey);
  

  printf("enc_size: %d\n", (char) enc_size);
  

  size_t aes_encrypt_size = (size + 15) & ~15;


  char* buffer = malloc(sizeof(char) * (aes_encrypt_size + enc_size + 1));

  buffer[0] = (char) enc_size;

  memcpy(buffer + 1, encrypt, enc_size);



  aes_encrypt(buffer + 1 + enc_size, message, size, aes_key, AES_256);


  file_write(buffer, aes_encrypt_size + enc_size + 1, args.args[1]);
}

/*
 *
 */
static void decrypt_handler(const void* message, size_t size, skey_t* skey)
{
  size_t enc_size = (size_t) *((uint8_t*) message);


  printf("enc_size: %ld\n", enc_size);


  char encrypt[enc_size];

  memcpy(encrypt, message + 1, enc_size);


  char decrypt[1024];
  memset(decrypt, '\0', sizeof(decrypt));

  size_t dec_size = 0;

  rsa_decrypt(decrypt, &dec_size, encrypt, enc_size, skey);
  

  printf("dec_size: %ld\n", dec_size);


  char* result = malloc(sizeof(char) * (size - 1 - enc_size));

  aes_decrypt(result, message + 1 + enc_size, (size - 1 - enc_size), decrypt, AES_256);

  file_write(result, (size - 1 - enc_size), args.args[1]);

  free(result);

  // file_write(message + 1 + enc_size, (size - 1 - enc_size), args.args[1]);
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

  printf("pkey:\n");
  gmp_printf("n: %Zd\n", pkey.n);
  gmp_printf("e: %Zd\n", pkey.e);

  printf("skey:\n");
  gmp_printf("n: %Zd\n", skey.n);
  gmp_printf("e: %Zd\n", skey.e);
  gmp_printf("d: %Zd\n", skey.d);
  gmp_printf("p: %Zd\n", skey.p);
  gmp_printf("q: %Zd\n", skey.q);


  // Get the size of the inputted file
  // If the size is 0 (no data), the file is of no use
  size_t size = file_size_get(args.args[0]);

  if(size == 0)
  {
    fprintf(stderr, "crypto: Inputted file has no data\n");
  
    keys_free(&skey, &pkey);

    return 1;
  }

  // Read the file and store the data as the message
  char* message = malloc(sizeof(char) * size);

  if(file_read(message, size, args.args[0]) == 0)
  {
    fprintf(stderr, "crypto: Failed to read file\n");

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
