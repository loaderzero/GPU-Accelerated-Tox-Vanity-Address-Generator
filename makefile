# Makefile for the Tox Vanity Address Generator

# Compiler and flags
CC = gcc
CFLAGS = -O2 -Wall -g # -O2 for optimization, -Wall for warnings, -g for debug symbols

# Linker flags (libraries to link against)
LDFLAGS = -ltoxcore -lsodium -lOpenCL -lpthread

# The target executable name
TARGET = tox_vanity_miner

# Default rule
all: $(TARGET)

# Rule to build the target
$(TARGET): tox.c
	$(CC) $(CFLAGS) -o $(TARGET) tox.c $(LDFLAGS)

# Rule to clean up build files
clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
