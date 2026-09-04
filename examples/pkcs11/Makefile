# acvp-assay PKCS#11 reference harness.
#
# No dependencies beyond libdl and a PKCS#11 header. If your SDK ships its own
# headers, point PKCS11_INCLUDE at them instead of p11-kit's.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c99
PKCS11_INCLUDE ?= /usr/include/p11-kit-1
LDLIBS  := -ldl

acvp_harness: acvp_harness.c
	$(CC) $(CFLAGS) -I$(PKCS11_INCLUDE) -o $@ $< $(LDLIBS)

clean:
	rm -f acvp_harness

.PHONY: clean
