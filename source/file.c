/*
 * file.c
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-11-21
 */

#include "file.h"

/*
 * Get the size of a file
 *
 * The function returns the number of bytes in the file
 *
 * PARAMS
 * - const char* filepath | Path to file
 *
 * RETURN (size_t size)
 * - 0  | Error
 * - >0 | Success
 */
size_t file_size_get(const char* filepath)
{
  FILE* stream = fopen(filepath, "rb");

  if(!stream) return 0;

  fseek(stream, 0, SEEK_END); 

  size_t size = ftell(stream);

  fseek(stream, 0, SEEK_SET); 

  fclose(stream);

  return size;
}

/*
 * Write a number of bytes from memory at pointer to file
 *
 * The function returns the number of written bytes
 *
 * PARAMS
 * - const void* pointer  | Address to write data to
 * - size_t      size     | Number of bytes to write
 * - const char* filepath | Path to file
 *
 * RETURN (same as fwrite, size_t write_size)
 * - 0  | Error
 * - >0 | Success!
 */
size_t file_write(const void* pointer, size_t size, const char* filepath)
{
  if(!pointer) return 0;

  FILE* stream = fopen(filepath, "wb");

  if(!stream) return 0;

  size_t write_size = fwrite(pointer, 1, size, stream);

  fclose(stream);

  return write_size;
}

/*
 * Read a number of bytes from file to memory at pointer
 *
 * The function returns the number of read bytes
 *
 * PARAMS
 * - void*       pointer  | Address to store read data
 * - size_t      size     | Number of bytes to read
 * - const char* filepath | Path to file
 *
 * RETURN (same as fread, size_t read_size)
 * - 0  | Error
 * - >0 | Success!
 */
size_t file_read(void* pointer, size_t size, const char* filepath)
{
  if(!pointer) return 0;

  FILE* stream = fopen(filepath, "rb");

  if(stream == NULL) return 0;

  int status = fread(pointer, 1, size, stream);

  fclose(stream);

  return status;
}

/*
 *
 */
size_t dir_file_read(void* pointer, size_t size, const char* dirpath, const char* name)
{
  size_t path_size = strlen(dirpath) + 1 + strlen(name);

  char filepath[path_size + 1];

  sprintf(filepath, "%s/%s", dirpath, name);

  return file_read(pointer, size, filepath);
}

/*
 *
 */
size_t dir_file_write(const void* pointer, size_t size, const char* dirpath, const char* name)
{
  size_t path_size = strlen(dirpath) + 1 + strlen(name);

  char filepath[path_size + 1];

  sprintf(filepath, "%s/%s", dirpath, name);

  return file_write(pointer, size, filepath);
}

/*
 *
 */
size_t dir_file_size_get(const char* dirpath, const char* name)
{
  size_t path_size = strlen(dirpath) + 1 + strlen(name);

  char filepath[path_size + 1];

  sprintf(filepath, "%s/%s", dirpath, name);

  return file_size_get(filepath);
}
