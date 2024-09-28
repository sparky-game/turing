#ifndef TURING_SHA256_H_
#define TURING_SHA256_H_

#define SHA256_BLOCK_SIZE 32

void sha256(char *out, const char *in);

#endif  // TURING_SHA256_H_

#ifdef TURING_IMPLEMENTATION
#include "../../src/sha256.c"
#endif  // TURING_IMPLEMENTATION
