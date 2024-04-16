#include "../file.h"

/*
 * Get the size of the data in a file at the inputted path
 *
 * PARAMS
 * - const char* filepath | The path to the file
 *
 * RETURN (size_t size)
 * - 0  | Error
 * - >0 | Success!
 */
size_t file_size(const char* filepath)
{
  FILE* stream = fopen(filepath, "rb");

  if(stream == NULL) return 0;

  fseek(stream, 0, SEEK_END); 

  size_t size = ftell(stream);

  fseek(stream, 0, SEEK_SET); 

  fclose(stream);

  return size;
}

/*
 * Write data to file and store it at the inputted filepath
 *
 * PARAMS
 * - const void* pointer  | The address to the data to write
 * - size_t size          | The size of the data to write
 * - size_t nmemb         | The size of the chunks
 * - const char* filepath | The path to the file
 *
 * RETURN (same as fwrite)
 * - 0  | Error
 * - >0 | Success!
 */
int file_write(const void* pointer, size_t size, size_t nmemb, const char* filepath)
{
  FILE* stream = fopen(filepath, "wb");

  if(stream == NULL) return 0;

  int status = fwrite(pointer, size, nmemb, stream);

  fclose(stream);

  return status;
}

/*
 * Read data from file and store it at the inputted filepath
 *
 * PARAMS
 * - void* pointer        | The address to store the read data
 * - size_t size          | The size of the data to read
 * - size_t nmemb         | The size of the chunks
 * - const char* filepath | The path to the file
 *
 * RETURN (same as fread)
 * - 0  | Error
 * - >0 | Success!
 */
int file_read(void* pointer, size_t size, size_t nmemb, const char* filepath)
{
  FILE* stream = fopen(filepath, "rb");

  if(stream == NULL) return 0;

  int status = fread(pointer, size, nmemb, stream);

  fclose(stream);

  return status;
}

/*
 * RETURN (same as file_read)
 */
int file_dir_read(void* pointer, size_t size, size_t nmemb, const char* dir, const char* name)
{
  char filepath[1024];
  sprintf(filepath, "%s/%s", dir, name);

  return file_read(pointer, size, nmemb, filepath);
}

/*
 * RETURN (same as file_write)
 */
int file_dir_write(const void* pointer, size_t size, size_t nmemb, const char* dir, const char* name)
{
  char filepath[1024];
  sprintf(filepath, "%s/%s", dir, name);

  return file_write(pointer, size, nmemb, filepath);
}
