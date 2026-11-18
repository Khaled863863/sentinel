# Sentinel - CMPS 241 project
#
#   make            build everything (sentinel, sentinel-server, sentinel-client)
#   make test       build and run the unit tests
#   make memcheck   run a scripted session of sentinel under Valgrind
#   make run        start sentinel with its data in ./data
#   make install    copy the programs to /usr/local/bin (used on Alpine)
#   make clean      remove everything that was built

CC       ?= gcc
CFLAGS   ?= -std=c11 -Wall -Wextra -Wpedantic -g -O0
CFLAGS   += -pthread
CPPFLAGS += -Iinclude -D_POSIX_C_SOURCE=200809L -MMD -MP
LDLIBS   += -pthread
PREFIX   ?= /usr/local

BUILD := build

CORE_OBJ := $(BUILD)/input.o $(BUILD)/hash.o $(BUILD)/auth.o $(BUILD)/access.o \
            $(BUILD)/logger.o $(BUILD)/ui.o $(BUILD)/ids.o $(BUILD)/attacker.o \
            $(BUILD)/simulation.o

PROGRAMS := sentinel sentinel-server sentinel-client

.PHONY: all test memcheck run install clean

all: $(PROGRAMS)

sentinel: $(CORE_OBJ) $(BUILD)/main.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

sentinel-server: $(BUILD)/server.o $(BUILD)/net.o $(BUILD)/input.o $(BUILD)/hash.o \
                 $(BUILD)/auth.o $(BUILD)/access.o $(BUILD)/logger.o $(BUILD)/ids.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

sentinel-client: $(BUILD)/client.o $(BUILD)/net.o $(BUILD)/input.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/test_sentinel: $(BUILD)/test_sentinel.o $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# Each .c file is compiled on its own; -MMD writes a .d file listing the
# headers it uses, so changing a header rebuilds exactly the files that need it.
$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/test_sentinel.o: tests/test_sentinel.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD):
	mkdir -p $(BUILD)

test: $(BUILD)/test_sentinel
	./$(BUILD)/test_sentinel

memcheck: sentinel
	rm -rf $(BUILD)/memcheck-data && mkdir -p $(BUILD)/memcheck-data
	SENTINEL_DIR=$(BUILD)/memcheck-data SENTINEL_SEED=7 \
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=1 \
	./sentinel < tests/demo_input.txt > $(BUILD)/memcheck-output.txt
	@echo "Valgrind finished with no errors. Program output: $(BUILD)/memcheck-output.txt"

run: sentinel
	mkdir -p data
	SENTINEL_DIR=data ./sentinel

install: all
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(PROGRAMS) $(DESTDIR)$(PREFIX)/bin/

clean:
	rm -rf $(BUILD) $(PROGRAMS)

-include $(wildcard $(BUILD)/*.d)
