# acvp-assay liboqs harness.
#
# Needs a built liboqs. Point LIBOQS at an install prefix (the directory with
# include/oqs and lib/liboqs.a), or set LIBOQS_INCLUDE and LIBOQS_LIB apart.
#
#     make LIBOQS=$HOME/liboqs-install
#
# The static archive is linked --whole-archive on purpose. The entry points
# below OQS_API are referenced weakly, and a weak reference does not pull an
# object out of an archive: without this the symbols link to null, every ML-DSA
# operation declines, and the failure looks exactly like a liboqs that lacks
# them. Linking everything in costs about 800 KB and removes that trap.
#
# LIBOQS_COMMIT is recorded in the harness's metadata and in --capabilities. It
# is not guessed: pass it, or leave it out and the version stands alone.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
LIBOQS  ?= /usr/local
LIBOQS_INCLUDE ?= $(LIBOQS)/include
LIBOQS_LIB     ?= $(LIBOQS)/lib/liboqs.a
LIBOQS_COMMIT  ?=

DEFINES := -DACVP_HARNESS_CC='"$(shell $(CC) --version 2>/dev/null | head -1)"' \
           -DACVP_HARNESS_CFLAGS='"$(CFLAGS)"' \
           -DACVP_LIBOQS_COMMIT='"$(LIBOQS_COMMIT)"'

acvp_harness: acvp_harness.c
	$(CC) $(CFLAGS) $(DEFINES) -I$(LIBOQS_INCLUDE) -o $@ $< \
	    -Wl,--whole-archive $(LIBOQS_LIB) -Wl,--no-whole-archive -lm

capabilities.json: acvp_harness
	./acvp_harness --capabilities > $@

clean:
	rm -f acvp_harness

.PHONY: clean
