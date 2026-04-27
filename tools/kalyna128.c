/*
 * Kalyna-128/128 reference implementation (DSTU 7624:2014).
 *
 * Specialised to block = key = 128 bit, 10 rounds — just enough for the
 * hashcat -m 36000 hash generator and self-test.
 *
 * Adapted from the MIT-licensed multi-variant reference by R. Kiianchuk,
 * R. Mordvinov, R. Oliynykov (https://github.com/rkiyanchuk/kalyna). The S-box
 * tables in kalyna_tables.h are taken verbatim from that reference.
 */
#include "kalyna128.h"
#include "kalyna_tables.h"

#include <string.h>

/* GF(2^8) reduction polynomial (x^8 + x^4 + x^3 + x^2 + 1). */
#define KALYNA_REDUCTION 0x011d

/* MDS matrix used by MixColumns and its inverse. */
static const uint8_t mds_matrix[8][8] = {
    {0x01,0x01,0x05,0x01,0x08,0x06,0x07,0x04},
    {0x04,0x01,0x01,0x05,0x01,0x08,0x06,0x07},
    {0x07,0x04,0x01,0x01,0x05,0x01,0x08,0x06},
    {0x06,0x07,0x04,0x01,0x01,0x05,0x01,0x08},
    {0x08,0x06,0x07,0x04,0x01,0x01,0x05,0x01},
    {0x01,0x08,0x06,0x07,0x04,0x01,0x01,0x05},
    {0x05,0x01,0x08,0x06,0x07,0x04,0x01,0x01},
    {0x01,0x05,0x01,0x08,0x06,0x07,0x04,0x01}
};

static const uint8_t mds_inv_matrix[8][8] = {
    {0xAD,0x95,0x76,0xA8,0x2F,0x49,0xD7,0xCA},
    {0xCA,0xAD,0x95,0x76,0xA8,0x2F,0x49,0xD7},
    {0xD7,0xCA,0xAD,0x95,0x76,0xA8,0x2F,0x49},
    {0x49,0xD7,0xCA,0xAD,0x95,0x76,0xA8,0x2F},
    {0x2F,0x49,0xD7,0xCA,0xAD,0x95,0x76,0xA8},
    {0xA8,0x2F,0x49,0xD7,0xCA,0xAD,0x95,0x76},
    {0x76,0xA8,0x2F,0x49,0xD7,0xCA,0xAD,0x95},
    {0x95,0x76,0xA8,0x2F,0x49,0xD7,0xCA,0xAD}
};

/* ---------- helpers ---------- */

static uint64_t load64_le (const uint8_t *p)
{
    return ((uint64_t) p[0])       | ((uint64_t) p[1] <<  8)
         | ((uint64_t) p[2] << 16) | ((uint64_t) p[3] << 24)
         | ((uint64_t) p[4] << 32) | ((uint64_t) p[5] << 40)
         | ((uint64_t) p[6] << 48) | ((uint64_t) p[7] << 56);
}

static void store64_le (uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t) v;
    p[1] = (uint8_t) (v >>  8);
    p[2] = (uint8_t) (v >> 16);
    p[3] = (uint8_t) (v >> 24);
    p[4] = (uint8_t) (v >> 32);
    p[5] = (uint8_t) (v >> 40);
    p[6] = (uint8_t) (v >> 48);
    p[7] = (uint8_t) (v >> 56);
}

static uint8_t gf_mul (uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1u) r ^= a;
        uint8_t hi = a & 0x80u;
        a = (uint8_t) (a << 1);
        if (hi) a ^= (uint8_t) KALYNA_REDUCTION;
        b >>= 1;
    }
    return r;
}

/* ---------- core round transformations on a 2-word state ---------- */

static void sub_bytes_enc (uint64_t s[2])
{
    for (int i = 0; i < 2; ++i) {
        uint64_t v = s[i];
        s[i] = (uint64_t) sboxes_enc[0][(v >>  0) & 0xff]
             | ((uint64_t) sboxes_enc[1][(v >>  8) & 0xff] <<  8)
             | ((uint64_t) sboxes_enc[2][(v >> 16) & 0xff] << 16)
             | ((uint64_t) sboxes_enc[3][(v >> 24) & 0xff] << 24)
             | ((uint64_t) sboxes_enc[0][(v >> 32) & 0xff] << 32)
             | ((uint64_t) sboxes_enc[1][(v >> 40) & 0xff] << 40)
             | ((uint64_t) sboxes_enc[2][(v >> 48) & 0xff] << 48)
             | ((uint64_t) sboxes_enc[3][(v >> 56) & 0xff] << 56);
    }
}

static void sub_bytes_dec (uint64_t s[2])
{
    for (int i = 0; i < 2; ++i) {
        uint64_t v = s[i];
        s[i] = (uint64_t) sboxes_dec[0][(v >>  0) & 0xff]
             | ((uint64_t) sboxes_dec[1][(v >>  8) & 0xff] <<  8)
             | ((uint64_t) sboxes_dec[2][(v >> 16) & 0xff] << 16)
             | ((uint64_t) sboxes_dec[3][(v >> 24) & 0xff] << 24)
             | ((uint64_t) sboxes_dec[0][(v >> 32) & 0xff] << 32)
             | ((uint64_t) sboxes_dec[1][(v >> 40) & 0xff] << 40)
             | ((uint64_t) sboxes_dec[2][(v >> 48) & 0xff] << 48)
             | ((uint64_t) sboxes_dec[3][(v >> 56) & 0xff] << 56);
    }
}

/*
 * ShiftRows for nb=2: bytes are arranged as state[row + col*8].
 * Spec shifts each row by floor(row * nb / 8). For nb=2 this is 0 for rows 0..3
 * and 1 for rows 4..7, i.e. swap the high 32 bits of column 0 and column 1.
 * Same swap is its own inverse.
 */
static void shift_rows (uint64_t s[2])
{
    uint64_t lo0 = s[0] & 0x00000000FFFFFFFFULL;
    uint64_t hi0 = s[0] & 0xFFFFFFFF00000000ULL;
    uint64_t lo1 = s[1] & 0x00000000FFFFFFFFULL;
    uint64_t hi1 = s[1] & 0xFFFFFFFF00000000ULL;
    s[0] = lo0 | hi1;
    s[1] = lo1 | hi0;
}

#define inv_shift_rows shift_rows

static void mix_columns_with (uint64_t s[2], const uint8_t m[8][8])
{
    uint8_t bytes[16];
    store64_le (bytes + 0, s[0]);
    store64_le (bytes + 8, s[1]);
    for (int col = 0; col < 2; ++col) {
        uint64_t result = 0;
        for (int row = 7; row >= 0; --row) {
            uint8_t product = 0;
            for (int b = 7; b >= 0; --b) {
                product ^= gf_mul (bytes[b + col * 8], m[row][b]);
            }
            result |= ((uint64_t) product) << (row * 8);
        }
        s[col] = result;
    }
}

static void mix_columns     (uint64_t s[2]) { mix_columns_with (s, mds_matrix);     }
static void inv_mix_columns (uint64_t s[2]) { mix_columns_with (s, mds_inv_matrix); }

static void encipher_round (uint64_t s[2])
{
    sub_bytes_enc (s);
    shift_rows (s);
    mix_columns (s);
}

static void decipher_round (uint64_t s[2])
{
    inv_mix_columns (s);
    inv_shift_rows (s);
    sub_bytes_dec (s);
}

static void add_words (uint64_t dst[2], const uint64_t src[2])
{
    dst[0] += src[0];
    dst[1] += src[1];
}

static void sub_words (uint64_t dst[2], const uint64_t src[2])
{
    dst[0] -= src[0];
    dst[1] -= src[1];
}

static void xor_words (uint64_t dst[2], const uint64_t src[2])
{
    dst[0] ^= src[0];
    dst[1] ^= src[1];
}

/* Rotate the 16-byte buffer left by 7 bytes (used for odd round keys). */
static void rotate_left_7 (uint64_t s[2])
{
    uint8_t buf[16];
    store64_le (buf + 0, s[0]);
    store64_le (buf + 8, s[1]);
    uint8_t tmp[7];
    memcpy (tmp, buf, 7);
    memmove (buf, buf + 7, 9);
    memcpy (buf + 9, tmp, 7);
    s[0] = load64_le (buf + 0);
    s[1] = load64_le (buf + 8);
}

/* ---------- key schedule ---------- */

static void key_expand_kt (const uint64_t key[2], uint64_t kt[2])
{
    uint64_t state[2] = { 0, 0 };
    state[0] += (uint64_t) (KALYNA128_NB + KALYNA128_NK + 1); /* = 5 */

    add_words (state, key);
    encipher_round (state);
    xor_words (state, key);
    encipher_round (state);
    add_words (state, key);
    encipher_round (state);

    kt[0] = state[0];
    kt[1] = state[1];
}

static void key_expand_even (const uint64_t key[2], const uint64_t kt[2],
                             uint64_t round_keys[KALYNA128_NR + 1][2])
{
    uint64_t initial_data[2] = { key[0], key[1] };
    uint64_t tmv[2] = { 0x0001000100010001ULL, 0x0001000100010001ULL };
    int round = 0;

    for (;;) {
        uint64_t kt_round[2] = { kt[0], kt[1] };
        add_words (kt_round, tmv);

        uint64_t state[2] = { initial_data[0], initial_data[1] };
        add_words (state, kt_round);
        encipher_round (state);
        xor_words (state, kt_round);
        encipher_round (state);
        add_words (state, kt_round);

        round_keys[round][0] = state[0];
        round_keys[round][1] = state[1];

        if (round == KALYNA128_NR) break;

        round += 2;
        tmv[0] <<= 1;
        tmv[1] <<= 1;
        /* For nk=2, Rotate({a,b}) -> {b,a}. */
        uint64_t t = initial_data[0];
        initial_data[0] = initial_data[1];
        initial_data[1] = t;
    }
}

static void key_expand_odd (uint64_t round_keys[KALYNA128_NR + 1][2])
{
    for (int i = 1; i < KALYNA128_NR; i += 2) {
        round_keys[i][0] = round_keys[i - 1][0];
        round_keys[i][1] = round_keys[i - 1][1];
        rotate_left_7 (round_keys[i]);
    }
}

void kalyna128_set_key (kalyna128_ctx *ctx, const uint8_t key[KALYNA128_KEY_BYTES])
{
    uint64_t k[2];
    k[0] = load64_le (key + 0);
    k[1] = load64_le (key + 8);

    uint64_t kt[2];
    key_expand_kt (k, kt);
    key_expand_even (k, kt, ctx->round_keys);
    key_expand_odd (ctx->round_keys);
}

/* ---------- public encrypt / decrypt ---------- */

void kalyna128_encrypt (const kalyna128_ctx *ctx,
                        const uint8_t in[KALYNA128_BLOCK_BYTES],
                        uint8_t out[KALYNA128_BLOCK_BYTES])
{
    uint64_t s[2];
    s[0] = load64_le (in + 0);
    s[1] = load64_le (in + 8);

    /* round 0: addition mod 2^64 */
    add_words (s, ctx->round_keys[0]);

    for (int r = 1; r < KALYNA128_NR; ++r) {
        encipher_round (s);
        xor_words (s, ctx->round_keys[r]);
    }
    encipher_round (s);
    add_words (s, ctx->round_keys[KALYNA128_NR]);

    store64_le (out + 0, s[0]);
    store64_le (out + 8, s[1]);
}

void kalyna128_decrypt (const kalyna128_ctx *ctx,
                        const uint8_t in[KALYNA128_BLOCK_BYTES],
                        uint8_t out[KALYNA128_BLOCK_BYTES])
{
    uint64_t s[2];
    s[0] = load64_le (in + 0);
    s[1] = load64_le (in + 8);

    sub_words (s, ctx->round_keys[KALYNA128_NR]);
    for (int r = KALYNA128_NR - 1; r > 0; --r) {
        decipher_round (s);
        xor_words (s, ctx->round_keys[r]);
    }
    decipher_round (s);
    sub_words (s, ctx->round_keys[0]);

    store64_le (out + 0, s[0]);
    store64_le (out + 8, s[1]);
}
