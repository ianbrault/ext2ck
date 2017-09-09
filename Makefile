# Makefile
# Ian Brault <ianbrault@ucla.edu>

# compiler flags
CC = gcc
CFLAGS = -O2 -Wall -Wextra -Werror

# files
EXE = ext2ck
OBJ = ext2ck.o
SRC = ext2ck.c
INC = ext2.h
PY  = ext2ck.py


.PHONY: all clean

all: $(EXE)

$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $<

$(OBJ): $(SRC) $(INC)
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf $(EXE) *.o
