/*
 * crypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include "aes.h"
#include "file.h"

bool encrypt = true;

char* input  = NULL;
char* output = NULL;

char* cipher = NULL;
char* kfile  = NULL;

/*
 * Output text when something is wrong with an option
 */
void opt_wrong(void)
{
  if(optopt == 'a')
    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
  else if(isprint(optopt))
    fprintf(stderr, "Unknown option `-%c'.\n", optopt);
  else
    fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
}

/*
 * PARAMS
 * - int opt | The option to parse
 *
 * RETURN (int status)
 * - 0 | Success!
 * - 1 | Something wrong with option
 */
int opt_parse(int opt)
{
  switch(opt)
  {
    case 'e': encrypt = true; break;

    case 'd': encrypt = false; break;

    case 'c': cipher = optarg; break;

    case 'k': kfile = optarg; break;

    case '?': opt_wrong(); return 1;

    default : abort();
  }
  return 0; // Success!
}

/*
 * PARAMS (same as main)
 * - int argc     | The amount of arguments
 * - char* argv[] | The array of arguments
 *
 * RETURN
 * - 0 | Success!
 * - 1 | No input and output file was supplied
 */
int args_parse(int argc, char* argv[])
{
  opterr = 0;

  int opt;
  while((opt = getopt(argc, argv, "edc:k:")) != -1)
  {
    if(opt_parse(opt) != 0) return 1;
  }

  if(optind > (argc - 2)) return 1;

  input  = argv[optind++];
  output = argv[optind++];

  return 0; // Success!
}

/*
 *
 */
void aes_encrypt_handler(const char* message, size_t size, const char* key, ksize_t ksize)
{
  char result[size + 16 - (size % 16)];
  memset(result, '\0', sizeof(result));
  
  aes_encrypt(result, message, size, key, ksize);

  file_write(result, sizeof(result), 1, output);
}

/*
 *
 */
void aes_decrypt_handler(const char* message, size_t size, const char* key, ksize_t ksize)
{
  char result[size];
  memset(result, '\0', sizeof(result));
  
  aes_decrypt(result, message, size, key, ksize);
  
  file_write(result, sizeof(result), 1, output);
}

/*
 *
 */
int key_input(char* key, size_t size)
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
void key_get(char* key, size_t size)
{
  if(kfile) file_read(key, size, 1, kfile);

  else key_input(key, size);
}

/*
 * RETURN (int status)
 * - 0 | Success!
 * - 1 | No key was inputted
 */
int aes128_handler(const char* message, size_t size)
{
  size_t ksize = (kfile) ? file_size(kfile) : 16;

  char key[ksize + 1];
  memset(key, '\0', sizeof(key));

  key_get(key, ksize);

  if(encrypt) aes_encrypt_handler(message, size, key, AES_128);

  else        aes_decrypt_handler(message, size, key, AES_128);

  return 0; // Success!
}

/*
 * RETURN (int status)
 * - 0 | Success!
 * - 1 | No key was inputted
 */
int aes192_handler(const char* message, size_t size)
{
  size_t ksize = (kfile) ? file_size(kfile) : 24;

  char key[ksize + 1];
  memset(key, '\0', sizeof(key));

  key_get(key, ksize);

  if(encrypt) aes_encrypt_handler(message, size, key, AES_192);

  else        aes_decrypt_handler(message, size, key, AES_192);

  return 0; // Success!
}

/*
 * RETURN (int status)
 * - 0 | Success!
 * - 1 | No key was inputted
 */
int aes256_handler(const char* message, size_t size)
{
  size_t ksize = (kfile) ? file_size(kfile) : 32;

  char key[ksize + 1];
  memset(key, '\0', sizeof(key));

  key_get(key, ksize);

  if(encrypt) aes_encrypt_handler(message, size, key, AES_256);

  else        aes_decrypt_handler(message, size, key, AES_256);

  return 0; // Success!
}

/*
 * RETURNS
 * - 0 | Success!
 * - 1 | Failed to parse arguments
 * - 2 | Supplied input file is empty
 */
int main(int argc, char* argv[])
{
  if(args_parse(argc, argv) != 0) return 1;

  size_t size = file_size(input);
  if(size == 0) return 2;

  char message[size + 1];
  memset(message, '\0', sizeof(message));

  file_read(message, size, 1, input);

  if(cipher == NULL || !strcmp(cipher, "aes256"))
  {
    aes256_handler(message, size);
  }
  else if(!strcmp(cipher, "aes128"))
  {
    aes128_handler(message, size);
  }
  else if(!strcmp(cipher, "aes192"))
  {
    aes192_handler(message, size);
  }
  else if(!strcmp(cipher, "rsa"))
  {

  }
  else printf("Supplied cipher not supported.\n");

  return 0; // Success!
}
