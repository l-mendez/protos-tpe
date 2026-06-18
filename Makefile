include ./Makefile.inc

SERVER_SOURCES=$(wildcard src/server/*.c)
CLIENT_SOURCES=$(wildcard src/client/*.c)
SHARED_SOURCES=$(wildcard src/shared/*.c)
TEST_SOURCES=$(wildcard test/*_test.c)

SERVER_OBJECTS=$(SERVER_SOURCES:src/%.c=obj/%.o)
CLIENT_OBJECTS=$(CLIENT_SOURCES:src/%.c=obj/%.o)
SHARED_OBJECTS=$(SHARED_SOURCES:src/%.c=obj/%.o)

BIN=bin
OBJ=obj

SERVER_BIN=$(BIN)/server
CLIENT_BIN=$(BIN)/client
SHARED_LIB=$(OBJ)/libshared.a
TEST_BINS=$(TEST_SOURCES:test/%.c=$(BIN)/test/%)

.PHONY: all server client test clean

all: server client

server: $(SERVER_BIN)
client: $(CLIENT_BIN)

$(SERVER_BIN): $(SERVER_OBJECTS) $(SHARED_OBJECTS)
	@mkdir -p $(@D)
	$(COMPILER) $(COMPILER_FLAGS) $^ -o $@ $(LD_FLAGS)

$(CLIENT_BIN): $(CLIENT_OBJECTS) $(SHARED_OBJECTS)
	@mkdir -p $(@D)
	$(COMPILER) $(COMPILER_FLAGS) $^ -o $@ $(LD_FLAGS)

obj/%.o: src/%.c
	@mkdir -p $(@D)
	$(COMPILER) $(COMPILER_FLAGS) -c $< -o $@

# Each test links against an archive of the shared objects; the linker pulls
# only the symbols a test leaves undefined, so tests that include a .c unit
# directly do not clash with the same unit in the archive.
$(SHARED_LIB): $(SHARED_OBJECTS)
	$(AR) rcs $@ $^

$(BIN)/test/%: test/%.c $(SHARED_LIB)
	@mkdir -p $(@D)
	$(COMPILER) $(COMPILER_FLAGS) $(TEST_CFLAGS) $< $(SHARED_LIB) -o $@ $(TEST_LD_FLAGS)

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do echo "== $$t =="; ./$$t || exit 1; done

clean:
	rm -rf $(BIN) $(OBJ)
