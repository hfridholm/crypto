COMPILER := gcc

COMPILE_FLAGS := -Wall -Werror -g -Og -std=gnu99 -oFast
LINKER_FLAGS  := -lm -lgmp

SOURCE_DIR := ../source
OBJECT_DIR := ../object
BINARY_DIR := ../binary

PROGRAMS := symcpt keygen asmcpt

default: $(PROGRAMS)

symcpt: %: $(OBJECT_DIR)/%.o $(SOURCE_DIR)/%.c
	$(COMPILER) $(OBJECT_DIR)/$@.o $(LINKER_FLAGS) -o $(BINARY_DIR)/$@

keygen: %: $(OBJECT_DIR)/%.o $(SOURCE_DIR)/%.c
	$(COMPILER) $(OBJECT_DIR)/$@.o $(LINKER_FLAGS) -o $(BINARY_DIR)/$@

asmcpt: %: $(OBJECT_DIR)/%.o $(SOURCE_DIR)/%.c
	$(COMPILER) $(OBJECT_DIR)/$@.o $(LINKER_FLAGS) -o $(BINARY_DIR)/$@

$(OBJECT_DIR)/%.o: $(SOURCE_DIR)/%.c 
	$(COMPILER) $< -c $(COMPILE_FLAGS) -o $@

.PRECIOUS: $(OBJECT_DIR)/%.o $(PROGRAMS)

clean:
	-rm 2>/dev/null $(OBJECT_DIR)/*.o $(PROGRAMS)
