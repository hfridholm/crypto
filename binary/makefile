#
# Written by Hampus Fridholm
#
# Last updated: 2024-08-31
#

# These are the names of the targets
CLEAN_TARGET := clean
HELP_TARGET := help

# These are the flags and command for the clean target
DELETE_CMD := rm

# This is the compiler and the compile flags you want to use
COMPILER := gcc
COMPILE_FLAGS := -Wall -Werror -g -Og -std=gnu99 -oFast
LINKER_FLAGS := -lm -lgmp

SOURCE_DIR := ../source
OBJECT_DIR := ../object
BINARY_DIR := ../binary

# These are the source files and object files for the AES library
AES_DIR := $(SOURCE_DIR)/aes
AES_SOURCE_FILES := $(wildcard $(AES_DIR)/*.c)

# These are the source files and object files for the RSA library
RSA_DIR := $(SOURCE_DIR)/rsa
RSA_SOURCE_FILES := $(wildcard $(RSA_DIR)/*.c)

CRYPTO_SOURCE_FILES := $(AES_SOURCE_FILES) $(RSA_SOURCE_FILES) $(SOURCE_DIR)/file.c $(SOURCE_DIR)/sha256.c
CRYPTO_OBJECT_FILES := $(addprefix $(OBJECT_DIR)/, $(notdir $(CRYPTO_SOURCE_FILES:.c=.o)))

KEYGEN_SOURCE_FILES := $(RSA_SOURCE_FILES) $(SOURCE_DIR)/file.c
KEYGEN_OBJECT_FILES := $(addprefix $(OBJECT_DIR)/, $(notdir $(KEYGEN_SOURCE_FILES:.c=.o)))

# These are the executable programs that you can create
PROGRAMS := crypto keygen

all: $(PROGRAMS)

crypto: %: $(OBJECT_DIR)/%.o $(SOURCE_DIR)/%.c $(CRYPTO_OBJECT_FILES) $(CRYPTO_SOURCE_FILES)
	$(COMPILER) $(OBJECT_DIR)/$@.o $(CRYPTO_OBJECT_FILES) $(LINKER_FLAGS) -o $(BINARY_DIR)/$@

keygen: %: $(OBJECT_DIR)/%.o $(SOURCE_DIR)/%.c $(KEYGEN_OBJECT_FILES) $(KEYGEN_SOURCE_FILES)
	$(COMPILER) $(OBJECT_DIR)/$@.o $(KEYGEN_OBJECT_FILES) $(LINKER_FLAGS) -o $(BINARY_DIR)/$@

# These are rules for compiling object files out of source files
$(OBJECT_DIR)/%.o: $(SOURCE_DIR)/*/%.c 
	$(COMPILER) $< -c $(COMPILE_FLAGS) -o $@

$(OBJECT_DIR)/%.o: $(SOURCE_DIR)/%.c 
	$(COMPILER) $< -c $(COMPILE_FLAGS) -o $@

# These are the files that should be cleaned
DELETE_FILES := $(OBJECT_DIR)/*.o $(PROGRAMS)

# These are the files that should be kept (not automatically deleted)
.PRECIOUS: $(OBJECT_DIR)/%.o $(PROGRAMS)

$(CLEAN_TARGET):
	$(DELETE_CMD) $(DELETE_FILES)

$(HELP_TARGET):
	@echo $(PROGRAMS) $(CLEAN_TARGET)
