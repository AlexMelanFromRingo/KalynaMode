CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99
TARGET  := kalyna_gen
OBJS    := kalyna.o kalyna_gen.o
TARGETS := $(TARGET) kalyna128_kernel_check

all: $(TARGET) kalyna128_kernel_check

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

kalyna128_kernel_check: kalyna128_kernel_check.c kalyna128.c kalyna128.h kalyna_tables.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ kalyna128_kernel_check.c kalyna128.c

%.o: %.c kalyna.h kalyna128.h kalyna_tables.h
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TARGET) kalyna128_kernel_check
	./$(TARGET) --selftest
	./kalyna128_kernel_check

clean:
	rm -f *.o $(TARGETS)

.PHONY: all test clean
