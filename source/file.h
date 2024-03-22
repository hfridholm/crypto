#ifndef FILE_H
#define FILE_H

#include <stdio.h>

extern int file_read(void* pointer, size_t size, size_t nmemb, const char* filepath);

extern int file_write(const void* pointer, size_t size, size_t nmemb, const char* filepath);

extern int file_dir_read(void* pointer, size_t size, size_t nmemb, const char* dir, const char* name);

extern int file_dir_write(const void* pointer, size_t size, size_t nmemb, const char* dir, const char* name);

#endif // FILE_H
