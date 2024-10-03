#include <turing/keccak256.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef struct {
  uint64_t hash[25];
  uint64_t msg[24];
  uint16_t rest;
} ctx_t;

static const uint8_t k[] = {
  1, 26, 94, 112, 31, 33, 121, 85, 14, 12, 53, 38, 63, 79, 93, 83, 82, 72, 22, 102, 121, 88, 33, 116,
  1, 6,  9,  22,  14, 20, 2,   12, 13, 19, 23, 15, 4,  24, 21, 8,  16, 5,  3,  18,  17,  11, 7,  10,
  1, 62, 28, 27,  36, 44, 6,   55, 20, 3,  10, 43, 25, 39, 41, 45, 15, 21, 8,  18,  2,   61, 56, 14
};

#define IS_ALIGNED_64(p) (0 == ((uintptr_t) (p) & 7))
#define ROTATE_LEFT64(x, y) ((x) << (y) ^ ((x) >> (64 - (y))))

static void init(ctx_t *ctx) {
  memset(ctx, 0, sizeof(ctx_t));
}

static uint64_t get_round_constant(uint8_t round) {
  uint64_t result = 0;
  uint8_t round_info = k[round];
  if (round_info & (1 << 6)) { result |= ((uint64_t) 1 << 63); }
  if (round_info & (1 << 5)) { result |= ((uint64_t) 1 << 31); }
  if (round_info & (1 << 4)) { result |= ((uint64_t) 1 << 15); }
  if (round_info & (1 << 3)) { result |= ((uint64_t) 1 << 7);  }
  if (round_info & (1 << 2)) { result |= ((uint64_t) 1 << 3);  }
  if (round_info & (1 << 1)) { result |= ((uint64_t) 1 << 1);  }
  if (round_info & (1 << 0)) { result |= ((uint64_t) 1 << 0);  }
  return result;
}

static void phase_theta(uint64_t* A) {
  uint64_t C[5], D[5];
  for (uint8_t i = 0; i < 5; ++i) {
    C[i] = A[i];
    for (uint8_t j = 5; j < 25; j += 5) C[i] ^= A[i + j];
  }
  for (uint8_t i = 0; i < 5; ++i) {
    D[i] = ROTATE_LEFT64(C[(i + 1) % 5], 1) ^ C[(i + 4) % 5];
  }
  for (uint8_t i = 0; i < 5; ++i) {
    for (uint8_t j = 0; j < 25; j += 5) {
      A[i + j] ^= D[i];
    }
  }
}

static void phase_pi(uint64_t* A) {
  uint64_t A1 = A[1];
  for (uint8_t i = 1; i < 24; ++i) {
    A[k[24 + i - 1]] = A[k[24 + i]];
  }
  A[10] = A1;
}

static void phase_chi(uint64_t* A) {
  for (uint8_t i = 0; i < 25; i += 5) {
    uint64_t A0 = A[i + 0], A1 = A[i + 1];
    A[i + 0] ^= ~A1 & A[i + 2];
    A[i + 1] ^= ~A[i + 2] & A[i + 3];
    A[i + 2] ^= ~A[3 + i] & A[i + 4];
    A[i + 3] ^= ~A[i + 4] & A0;
    A[i + 4] ^= ~A0 & A1;
  }
}

static void permutation(uint64_t* hash) {
  for (uint8_t round = 0; round < 24; ++round) {
    phase_theta(hash);
    for (uint8_t i = 1; i < 25; ++i) {
      hash[i] = ROTATE_LEFT64(hash[i], k[48 + i - 1]);
    }
    phase_pi(hash);
    phase_chi(hash);
    *hash ^= get_round_constant(round);
  }
}

static void process_block(uint64_t* hash, const uint64_t* block) {
  for (uint8_t i = 0; i < 17; ++i) hash[i] ^= block[i];
  permutation(hash);
}

static void update(ctx_t* ctx, const uint8_t* msg, uint16_t size) {
  uint16_t idx = ctx->rest;
  ctx->rest = (ctx->rest + size) % 136;
  if (idx) {
    uint16_t left = 136 - idx;
    memcpy((char*) ctx->msg + idx, msg, (size < left ? size : left));
    if (size < left) return;
    process_block(ctx->hash, ctx->msg);
    msg += left;
    size -= left;
  }
  while (size >= 136) {
    uint64_t* aligned_msg_block;
    if (IS_ALIGNED_64(msg)) aligned_msg_block = (uint64_t*)/*(void*)*/ msg;
    else {
      memcpy(ctx->msg, msg, 136);
      aligned_msg_block = ctx->msg;
    }
    process_block(ctx->hash, aligned_msg_block);
    msg += 136;
    size -= 136;
  }
  if (size) memcpy(ctx->msg, msg, size);
}

static void assemble(ctx_t* ctx, uint8_t* hash) {
  memset((char*) ctx->msg + ctx->rest, 0, 136 - ctx->rest);
  ((char*) ctx->msg)[ctx->rest] |= 0x01;
  ((char*) ctx->msg)[136 - 1]  |= 0x80;
  process_block(ctx->hash, ctx->msg);
  if (hash) memcpy(hash, ctx->hash, KECCAK256_BLOCK_SIZE);
}

void keccak256(char *out, const char *in) {
  ctx_t c;
  uint8_t hash[KECCAK256_BLOCK_SIZE];
  init(&c);
  update(&c, (const uint8_t *) in, strlen(in));
  assemble(&c, hash);
  for (size_t i = 0; i < KECCAK256_BLOCK_SIZE; ++i) {
    sprintf(&out[i * 2], "%02x", hash[i]);
  }
}
