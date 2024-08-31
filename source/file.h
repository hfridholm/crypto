#ifndef FILE_H
#define FILE_H

#include <stdio.h>

extern size_t file_size_get(const char* filepath);

extern size_t file_read(void* pointer, size_t size, const char* filepath);

extern size_t file_write(const void* pointer, size_t size, const char* filepath);

#endif // FILE_H
