/*
 * Kalyna (DSTU 7624:2014) — multi-variant host reference.
 *
 * Supports all five DSTU variants:
 *   - 128/128 (block 128, key 128, 10 rounds)
 *   - 128/256 (block 128, key 256, 14 rounds)
 *   - 256/256 (block 256, key 256, 14 rounds)
 *   - 256/512 (block 256, key 512, 18 rounds)
 *   - 512/512 (block 512, key 512, 18 rounds)
 *
 * Adapted from the MIT-licensed reference by R. Kiianchuk, R. Mordvinov,
 * R. Oliynykov (https://github.com/rkiyanchuk/kalyna).
 */
#ifndef KALYNA_H
#define KALYNA_H

#include <stddef.h>
#include <stdint.h>

#define KALYNA_MAX_NB 8

/* Each variant identified by (block_bits, key_bits). */
typedef struct {
    int nb;          /* block words   (2, 4, 8) */
    int nk;          /* key words     (2, 4, 8) */
    int nr;          /* rounds        (10, 14, 18) */
    uint64_t round_keys[19][KALYNA_MAX_NB];  /* (NR+1) * NB; 19 = max(NR)+1 */
} kalyna_ctx;

/* Initialise context with the given block and key sizes (in bits).
 * Returns 0 on success, -1 if the (block,key) pair is unsupported. */
int kalyna_init (kalyna_ctx *ctx, int block_bits, int key_bits);

/* Schedule round keys from `key`. The buffer must hold key_bits/8 bytes. */
void kalyna_set_key (kalyna_ctx *ctx, const uint8_t *key);

/* Encrypt one block. in/out must hold block_bits/8 bytes; may overlap. */
void kalyna_encrypt (const kalyna_ctx *ctx, const uint8_t *in, uint8_t *out);

/* Decrypt one block. */
void kalyna_decrypt (const kalyna_ctx *ctx, const uint8_t *in, uint8_t *out);

#endif /* KALYNA_H */
