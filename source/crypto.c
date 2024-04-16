/*
 *
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
  while((opt = getopt(argc, argv, "edck:")) != -1)
  {
    if(opt_parse(opt) != 0) return 1;
  }

  if(optind > (argc - 2)) return 1;

  input  = argv[optind++];
  output = argv[optind++];

  return 0; // Success!
}

/*
 * RETURN (int status)
 * - 0 | Success!
 * - 1 | No key was inputted
 */
int aes_handler(const char* message, size_t size)
{
  char result[size + 1];
  memset(result, '\0', sizeof(result));

  char* key;
  size_t ksize = 0;

  if(kfile)
  {
    ksize = file_size(kfile);

    key = malloc(sizeof(char) * (ksize + 1));
    memset(key, '\0', ksize + 1);

    file_read(key, ksize, 1, kfile);
  }
  else
  {
    key = malloc(sizeof(char) * 1024);
    memset(key, '\0', 1024);

    printf("Key: ");

    if(fgets(key, sizeof(key), stdin) == NULL)
    {
      printf("No key was inputted\n");

      return 1;
    }
  }

  if(encrypt) aes_encrypt(result, message, size, key);

  else        aes_decrypt(result, message, size, key);

  file_write(result, size, 1, output);

  free(key);

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

  if(cipher == NULL || !strcmp(cipher, "aes"))
  {
    aes_handler(message, size);
  }
  else if(!strcmp(cipher, "rsa"))
  {

  }
  else printf("Supplied cipher not supported.\n");

  return 0;
}
