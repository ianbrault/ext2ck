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
# Python files
PY  = ext2ck.py
PYC = ext2ck.pyc
PYCACHE = __pycache__
PYC_GEN = $(PYCACHE)/lab3b.cpython-35.pyc


.PHONY: all clean

all: $(EXE)

$(EXE): $(OBJ) $(PYC)
	$(CC) $(CFLAGS) -o $@ $<
	@echo -e "#!/bin/sh\npython3 $< \$$*" > $@
	@chmod 755 $@

$(OBJ): $(SRC) $(INC)
	$(CC) $(CFLAGS) -c $<

$(PYC): $(PY)
	python3 -m py_compile $(PY)
	@mv $(PYC_GEN) $(PYC)
	@rmdir $(PYCACHE)

clean:
	rm -rf $(EXE) $(PYCACHE) $(PYC) *.o
