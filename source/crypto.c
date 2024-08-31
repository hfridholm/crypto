/*
 * crypto - cryptography utillity
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-08-31
 */

#include "crypto.h"

static char doc[] = "crypto - cryptography utillity";

static char args_doc[] = "[INPUT] [OUTPUT]";

static struct argp_option options[] =
{
  { "cipher",   'c', "STRING", 0, "Cryptography cipher" },
  { "password", 'p', "STRING", 0, "Password" },
  { "passfile", 'f', "FILE",   0, "Password file" },
  { "encrypt",  'e', 0,        0, "Encrypt message" },
  { "decrypt",  'd', 0,        0, "Decrypt message" },
  { 0 }
};

struct args
{
  char* args[2];
  char* cipher;
  char* password;
  char* passfile;
  bool  encrypt;
};

struct args args =
{
  .cipher   = NULL,
  .password = NULL,
  .passfile = NULL,
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
      if(args->passfile) argp_usage(state);

      args->password = arg;
      break;

    case 'f':
      if(args->password) argp_usage(state);

      args->passfile = arg;
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

      if(!args->password && !args->passfile) argp_usage(state);

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
  
  aes_encrypt(result, message, size, key, key_size);

  file_write(result, sizeof(result), args.args[1]);
}

/*
 *
 */
static void aes_decrypt_handler(const char* message, size_t size, const char* key, size_t key_size)
{
  char result[size];
  
  aes_decrypt(result, message, size, key, key_size);
  
  file_write(result, sizeof(result), args.args[1]);
}

/*
 *
 */
static void pass_word_or_file_hash(char hash[64])
{
  if(args.passfile)
  {
    size_t file_size = file_size_get(args.passfile);

    char password[file_size + 2];
    
    file_read(password, file_size, args.passfile);

    sha256(hash, password, file_size);
  }
  else if(args.password)
  {
    sha256(hash, args.password, strlen(args.password));
  }
  else
  {
    memset(hash, '\0', sizeof(char) * 64);
  }
}

/*
 *
 */
static void aes128_handler(const char* message, size_t size)
{
  char key[16];
  char hash[64];

  pass_word_or_file_hash(hash);

  memcpy(key, hash, sizeof(char) * 16);

  if(args.encrypt) aes_encrypt_handler(message, size, key, AES_128);

  else             aes_decrypt_handler(message, size, key, AES_128);
}

/*
 *
 */
static void aes192_handler(const char* message, size_t size)
{
  char key[24];
  char hash[64];

  pass_word_or_file_hash(hash);

  memcpy(key, hash, sizeof(char) * 24);

  if(args.encrypt) aes_encrypt_handler(message, size, key, AES_192);

  else             aes_decrypt_handler(message, size, key, AES_192);
}

/*
 *
 */
static void aes256_handler(const char* message, size_t size)
{
  char key[32];
  char hash[64];

  pass_word_or_file_hash(hash);

  memcpy(key, hash, sizeof(char) * 32);

  if(args.encrypt) aes_encrypt_handler(message, size, key, AES_256);

  else             aes_decrypt_handler(message, size, key, AES_256);
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

  if(args.cipher == NULL) args.cipher = "aes256";

  if(!args.passfile && !args.password) args.password = "";


  size_t size = file_size_get(args.args[0]);

  if(size == 0) return 2;

  char message[size + 1];
  memset(message, '\0', sizeof(message));

  file_read(message, size, args.args[0]);


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
