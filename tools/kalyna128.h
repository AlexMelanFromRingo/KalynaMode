/*
 * Kalyna-128/128 reference (DSTU 7624:2014, block = key = 128 bit, 10 rounds).
 *
 * Single-variant, self-contained host implementation used by the hash
 * generator and self-test for the hashcat -m 36000 module.
 *
 * Adapted from the MIT-licensed reference by R. Kiianchuk, R. Mordvinov,
 * R. Oliynykov (https://github.com/rkiyanchuk/kalyna), trimmed to the 128/128
 * variant only and made standalone.
 */
#ifndef KALYNA128_H
#define KALYNA128_H

#include <stddef.h>
#include <stdint.h>

#define KALYNA128_BLOCK_BYTES 16
#define KALYNA128_KEY_BYTES   16
#define KALYNA128_NB          2  /* 64-bit words per block */
#define KALYNA128_NK          2  /* 64-bit words per key   */
#define KALYNA128_NR          10 /* rounds                 */

typedef struct {
    uint64_t round_keys[KALYNA128_NR + 1][KALYNA128_NB];
} kalyna128_ctx;

/* Schedule the round keys from a 16-byte key. */
void kalyna128_set_key (kalyna128_ctx *ctx, const uint8_t key[KALYNA128_KEY_BYTES]);

/* Encrypt one 16-byte block. in and out may overlap. */
void kalyna128_encrypt (const kalyna128_ctx *ctx,
                        const uint8_t in[KALYNA128_BLOCK_BYTES],
                        uint8_t out[KALYNA128_BLOCK_BYTES]);

/* Decrypt one 16-byte block. in and out may overlap. */
void kalyna128_decrypt (const kalyna128_ctx *ctx,
                        const uint8_t in[KALYNA128_BLOCK_BYTES],
                        uint8_t out[KALYNA128_BLOCK_BYTES]);

#endif /* KALYNA128_H */
