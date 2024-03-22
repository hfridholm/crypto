# These are the names of the targets
CLEAN_TARGET := clean
HELP_TARGET := help

# These are the flags and command for the clean target
DELETE_CMD := rm

# This is the compiler and the compile flags you want to use
COMPILER := gcc
COMPILE_FLAGS := -Wall -Werror -g -Og -std=gnu99 -oFast
LINKER_FLAGS := -lm

SOURCE_DIR := ../source
OBJECT_DIR := ../object
BINARY_DIR := ../binary

# These are the source files and object files for the AES library
AES_DIR := $(SOURCE_DIR)/aes

AES_SOURCE_FILES := $(wildcard $(AES_DIR)/*.c)
AES_OBJECT_FILES := $(addprefix $(OBJECT_DIR)/, $(notdir $(AES_SOURCE_FILES:.c=.o)))

# These are the source files and object files for the RSA library
RSA_DIR := $(SOURCE_DIR)/rsa

RSA_SOURCE_FILES := $(wildcard $(RSA_DIR)/*.c)
RSA_OBJECT_FILES := $(addprefix $(OBJECT_DIR)/, $(notdir $(RSA_SOURCE_FILES:.c=.o)))

# These are the source files and object files for the FILE library
FILE_DIR := $(SOURCE_DIR)/file

FILE_SOURCE_FILES := $(wildcard $(FILE_DIR)/*.c)
FILE_OBJECT_FILES := $(addprefix $(OBJECT_DIR)/, $(notdir $(FILE_SOURCE_FILES:.c=.o)))

all: encrypt decrypt keygen

encrypt: %: $(OBJECT_DIR)/%.o $(SOURCE_DIR)/%.c $(AES_OBJECT_FILES) $(AES_SOURCE_FILES) $(RSA_OBJECT_FILES) $(RSA_SOURCE_FILES)
	$(COMPILER) $(OBJECT_DIR)/$@.o $(AES_OBJECT_FILES) $(RSA_OBJECT_FILES) $(LINKER_FLAGS) -o $(BINARY_DIR)/$@

decrypt: %: $(OBJECT_DIR)/%.o $(SOURCE_DIR)/%.c $(AES_OBJECT_FILES) $(AES_SOURCE_FILES) $(RSA_OBJECT_FILES) $(RSA_SOURCE_FILES)
	$(COMPILER) $(OBJECT_DIR)/$@.o $(AES_OBJECT_FILES) $(RSA_OBJECT_FILES) $(LINKER_FLAGS) -o $(BINARY_DIR)/$@

keygen: %: $(OBJECT_DIR)/%.o $(SOURCE_DIR)/%.c $(RSA_OBJECT_FILES) $(RSA_SOURCE_FILES) $(FILE_OBJECT_FILES) $(FILE_SOURCE_FILES)
	$(COMPILER) $(OBJECT_DIR)/$@.o $(RSA_OBJECT_FILES) $(FILE_OBJECT_FILES) $(LINKER_FLAGS) -o $(BINARY_DIR)/$@

# These are rules for compiling object files out of source files
$(OBJECT_DIR)/%.o: $(SOURCE_DIR)/*/%.c 
	$(COMPILER) $< -c $(COMPILE_FLAGS) -o $@

$(OBJECT_DIR)/%.o: $(SOURCE_DIR)/%.c 
	$(COMPILER) $< -c $(COMPILE_FLAGS) -o $@

# These are the executable programs that you can create
PROGRAMS := $(patsubst %.c, %, $(notdir $(wildcard $(SOURCE_DIR)/*.c)))

# These are the files that should be cleaned
DELETE_FILES := $(OBJECT_DIR)/*.o $(PROGRAMS)

# These are the files that should be kept (not automatically deleted)
.PRECIOUS: $(OBJECT_DIR)/%.o $(PROGRAMS)

$(CLEAN_TARGET):
	$(DELETE_CMD) $(DELETE_FILES)

$(HELP_TARGET):
	@echo $(PROGRAMS) $(CLEAN_TARGET)
