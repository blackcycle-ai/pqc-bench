# Build the sign/verify harness against the homogeneous PQC OpenSSL prefix.
# PQC_PREFIX defaults to the repo symlink; override on the make line for other hosts.
PQC_PREFIX ?= $(abspath ../../../repo/openssl3-pqc)

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
INCS    := -I$(PQC_PREFIX)/include
LIBS    := -L$(PQC_PREFIX)/lib -lcrypto
RPATH   := -Wl,-rpath,$(PQC_PREFIX)/lib

bench_sign: bench_sign.c
	$(CC) $(CFLAGS) $(INCS) $< -o $@ $(LIBS) $(RPATH)

clean:
	rm -f bench_sign

.PHONY: clean
