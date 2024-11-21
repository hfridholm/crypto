/*
 * file.h
 *
 * Written by Hampus Fridholm
 *
 * Last updated: 2024-11-21
 */

#ifndef FILE_H
#define FILE_H

#include <stdio.h>
#include <string.h>

extern size_t file_size_get(const char* filepath);

extern size_t file_read(void* pointer, size_t size, const char* filepath);

extern size_t file_write(const void* pointer, size_t size, const char* filepath);


extern size_t dir_file_size_get(const char* dirpath, const char* name);

extern size_t dir_file_write(const void* pointer, size_t size, const char* dirpath, const char* name);

extern size_t dir_file_read(void* pointer, size_t size, const char* dirpath, const char* name);

#endif // FILE_H
