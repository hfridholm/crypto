#include "../file.h"

int file_write(const void* pointer, size_t size, size_t nmemb, const char* filepath)
{
  FILE* stream = fopen(filepath, "wb");

  int status = fwrite(pointer, size, nmemb, stream);

  fclose(stream);

  return status;
}

int file_read(void* pointer, size_t size, size_t nmemb, const char* filepath)
{
  FILE* stream = fopen(filepath, "rb");

  int status = fread(pointer, size, nmemb, stream);

  fclose(stream);

  return status;
}

int file_dir_read(void* pointer, size_t size, size_t nmemb, const char* dir, const char* name)
{
  char filepath[1024];
  sprintf(filepath, "%s/%s", dir, name);

  return file_read(pointer, size, nmemb, filepath);
}

int file_dir_write(const void* pointer, size_t size, size_t nmemb, const char* dir, const char* name)
{
  char filepath[1024];
  sprintf(filepath, "%s/%s", dir, name);

  return file_write(pointer, size, nmemb, filepath);
}
