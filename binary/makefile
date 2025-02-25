#
# Written by Hampus Fridholm
#
# Last updated: 2025-02-24
#

# This is the compiler and the compile flags you want to use
COMPILER := gcc

COMPILE_FLAGS := -Wall -Werror -g -Og -std=gnu99 -oFast
LINKER_FLAGS := -lm -lgmp

SOURCE_DIR := ../source
OBJECT_DIR := ../object
BINARY_DIR := ../binary

# These are the executable programs that you can create
PROGRAMS := symcpt keygen asmcpt

all: $(PROGRAMS)

symcpt: %: $(OBJECT_DIR)/%.o $(SOURCE_DIR)/%.c
	$(COMPILER) $(OBJECT_DIR)/$@.o $(LINKER_FLAGS) -o $(BINARY_DIR)/$@

keygen: %: $(OBJECT_DIR)/%.o $(SOURCE_DIR)/%.c
	$(COMPILER) $(OBJECT_DIR)/$@.o $(LINKER_FLAGS) -o $(BINARY_DIR)/$@

asmcpt: %: $(OBJECT_DIR)/%.o $(SOURCE_DIR)/%.c
	$(COMPILER) $(OBJECT_DIR)/$@.o $(LINKER_FLAGS) -o $(BINARY_DIR)/$@

# These are rules for compiling object files out of source files
$(OBJECT_DIR)/%.o: $(SOURCE_DIR)/*/%.c 
	$(COMPILER) $< -c $(COMPILE_FLAGS) -o $@

$(OBJECT_DIR)/%.o: $(SOURCE_DIR)/%.c 
	$(COMPILER) $< -c $(COMPILE_FLAGS) -o $@

# These are the files that should be kept (not automatically deleted)
.PRECIOUS: $(OBJECT_DIR)/%.o $(PROGRAMS)

clean:
	rm $(OBJECT_DIR)/*.o $(PROGRAMS)
