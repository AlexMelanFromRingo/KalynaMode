/*
 * Kalyna (DSTU 7624:2014) — multi-variant host reference.
 *
 * Adapted from the MIT-licensed reference by R. Kiianchuk, R. Mordvinov,
 * R. Oliynykov (https://github.com/rkiyanchuk/kalyna). The S-box tables in
 * kalyna_tables.h are taken verbatim from that reference.
 */
#include "kalyna.h"
#include "kalyna_tables.h"

#include <string.h>

#define KAL_RED 0x011d  /* GF(2^8) reduction polynomial */

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

static uint64_t load64 (const uint8_t *p)
{
    return ((uint64_t) p[0])       | ((uint64_t) p[1] <<  8)
         | ((uint64_t) p[2] << 16) | ((uint64_t) p[3] << 24)
         | ((uint64_t) p[4] << 32) | ((uint64_t) p[5] << 40)
         | ((uint64_t) p[6] << 48) | ((uint64_t) p[7] << 56);
}

static void store64 (uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t) (v >> (i * 8));
}

static uint8_t gf_mul (uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1u) r ^= a;
        uint8_t hi = a & 0x80u;
        a = (uint8_t) (a << 1);
        if (hi) a ^= (uint8_t) KAL_RED;
        b >>= 1;
    }
    return r;
}

/* ---------- core round transformations ---------- */

#define INDEX(arr, row, col) (arr)[(row) + (col) * 8]

static void sub_bytes_enc (kalyna_ctx *ctx, uint64_t *s)
{
    for (int i = 0; i < ctx->nb; ++i) {
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

static void sub_bytes_dec (kalyna_ctx *ctx, uint64_t *s)
{
    for (int i = 0; i < ctx->nb; ++i) {
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

static void shift_rows_dir (kalyna_ctx *ctx, uint64_t *s, int inverse)
{
    /* Spec: each row shifted left by floor(row * nb / 8). */
    uint8_t state[64], nstate[64];
    for (int i = 0; i < ctx->nb; ++i) store64 (state + i * 8, s[i]);

    int shift = -1;
    int rows_per_inc = 8 / ctx->nb;
    for (int row = 0; row < 8; ++row) {
        if (row % rows_per_inc == 0) shift += 1;
        for (int col = 0; col < ctx->nb; ++col) {
            int newcol = (col + shift) % ctx->nb;
            if (inverse)
                INDEX (nstate, row, col) = INDEX (state, row, newcol);
            else
                INDEX (nstate, row, newcol) = INDEX (state, row, col);
        }
    }
    for (int i = 0; i < ctx->nb; ++i) s[i] = load64 (nstate + i * 8);
}

static void shift_rows     (kalyna_ctx *ctx, uint64_t *s) { shift_rows_dir (ctx, s, 0); }
static void inv_shift_rows (kalyna_ctx *ctx, uint64_t *s) { shift_rows_dir (ctx, s, 1); }

static void mix_columns_with (kalyna_ctx *ctx, uint64_t *s, const uint8_t m[8][8])
{
    uint8_t state[64];
    for (int i = 0; i < ctx->nb; ++i) store64 (state + i * 8, s[i]);
    for (int col = 0; col < ctx->nb; ++col) {
        uint64_t result = 0;
        for (int row = 7; row >= 0; --row) {
            uint8_t product = 0;
            for (int b = 7; b >= 0; --b) {
                product ^= gf_mul (INDEX (state, b, col), m[row][b]);
            }
            result |= ((uint64_t) product) << (row * 8);
        }
        s[col] = result;
    }
}

static void mix_columns     (kalyna_ctx *ctx, uint64_t *s) { mix_columns_with (ctx, s, mds_matrix);     }
static void inv_mix_columns (kalyna_ctx *ctx, uint64_t *s) { mix_columns_with (ctx, s, mds_inv_matrix); }

static void encipher_round (kalyna_ctx *ctx, uint64_t *s)
{
    sub_bytes_enc (ctx, s);
    shift_rows (ctx, s);
    mix_columns (ctx, s);
}

static void decipher_round (kalyna_ctx *ctx, uint64_t *s)
{
    inv_mix_columns (ctx, s);
    inv_shift_rows (ctx, s);
    sub_bytes_dec (ctx, s);
}

static void add_words (uint64_t *dst, const uint64_t *src, int n)
{
    for (int i = 0; i < n; ++i) dst[i] += src[i];
}
static void sub_words (uint64_t *dst, const uint64_t *src, int n)
{
    for (int i = 0; i < n; ++i) dst[i] -= src[i];
}
static void xor_words (uint64_t *dst, const uint64_t *src, int n)
{
    for (int i = 0; i < n; ++i) dst[i] ^= src[i];
}

/* Rotate state_size 64-bit words left by (2 * nb + 3) bytes (used for odd round keys). */
static void rotate_left_bytes (uint64_t *s, int state_size_words, int rotate_bytes)
{
    int total = state_size_words * 8;
    uint8_t buf[64];
    for (int i = 0; i < state_size_words; ++i) store64 (buf + i * 8, s[i]);
    uint8_t tmp[64];
    memcpy (tmp, buf, rotate_bytes);
    memmove (buf, buf + rotate_bytes, total - rotate_bytes);
    memcpy (buf + total - rotate_bytes, tmp, rotate_bytes);
    for (int i = 0; i < state_size_words; ++i) s[i] = load64 (buf + i * 8);
}

/* Rotate words left by 1 (for KeyExpandEven). */
static void rotate_words (uint64_t *s, int n)
{
    uint64_t t = s[0];
    for (int i = 1; i < n; ++i) s[i - 1] = s[i];
    s[n - 1] = t;
}

/* ---------- key schedule ---------- */

static void key_expand_kt (kalyna_ctx *ctx, const uint64_t *key, uint64_t *kt)
{
    uint64_t state[KALYNA_MAX_NB];
    memset (state, 0, sizeof state);
    state[0] += (uint64_t) (ctx->nb + ctx->nk + 1);

    uint64_t k0[KALYNA_MAX_NB], k1[KALYNA_MAX_NB];
    if (ctx->nb == ctx->nk) {
        memcpy (k0, key, ctx->nb * sizeof (uint64_t));
        memcpy (k1, key, ctx->nb * sizeof (uint64_t));
    } else {
        memcpy (k0, key, ctx->nb * sizeof (uint64_t));
        memcpy (k1, key + ctx->nb, ctx->nb * sizeof (uint64_t));
    }

    add_words (state, k0, ctx->nb);
    encipher_round (ctx, state);
    xor_words (state, k1, ctx->nb);
    encipher_round (ctx, state);
    add_words (state, k0, ctx->nb);
    encipher_round (ctx, state);

    memcpy (kt, state, ctx->nb * sizeof (uint64_t));
}

static void key_expand_even (kalyna_ctx *ctx, const uint64_t *key, const uint64_t *kt)
{
    uint64_t initial_data[KALYNA_MAX_NB * 2];
    memcpy (initial_data, key, ctx->nk * sizeof (uint64_t));

    uint64_t tmv[KALYNA_MAX_NB];
    for (int i = 0; i < ctx->nb; ++i) tmv[i] = 0x0001000100010001ULL;

    int round = 0;
    for (;;) {
        uint64_t kt_round[KALYNA_MAX_NB];
        memcpy (kt_round, kt, ctx->nb * sizeof (uint64_t));
        add_words (kt_round, tmv, ctx->nb);

        uint64_t state[KALYNA_MAX_NB];
        memcpy (state, initial_data, ctx->nb * sizeof (uint64_t));
        add_words (state, kt_round, ctx->nb);
        encipher_round (ctx, state);
        xor_words (state, kt_round, ctx->nb);
        encipher_round (ctx, state);
        add_words (state, kt_round, ctx->nb);

        memcpy (ctx->round_keys[round], state, ctx->nb * sizeof (uint64_t));

        if (round == ctx->nr) break;

        if (ctx->nk != ctx->nb) {
            round += 2;

            for (int i = 0; i < ctx->nb; ++i) tmv[i] <<= 1;

            memcpy (kt_round, kt, ctx->nb * sizeof (uint64_t));
            add_words (kt_round, tmv, ctx->nb);

            memcpy (state, initial_data + ctx->nb, ctx->nb * sizeof (uint64_t));
            add_words (state, kt_round, ctx->nb);
            encipher_round (ctx, state);
            xor_words (state, kt_round, ctx->nb);
            encipher_round (ctx, state);
            add_words (state, kt_round, ctx->nb);

            memcpy (ctx->round_keys[round], state, ctx->nb * sizeof (uint64_t));

            if (round == ctx->nr) break;
        }
        round += 2;
        for (int i = 0; i < ctx->nb; ++i) tmv[i] <<= 1;
        rotate_words (initial_data, ctx->nk);
    }
}

static void key_expand_odd (kalyna_ctx *ctx)
{
    int rotate_bytes = 2 * ctx->nb + 3;
    for (int i = 1; i < ctx->nr; i += 2) {
        memcpy (ctx->round_keys[i], ctx->round_keys[i - 1], ctx->nb * sizeof (uint64_t));
        rotate_left_bytes (ctx->round_keys[i], ctx->nb, rotate_bytes);
    }
}

/* ---------- public API ---------- */

int kalyna_init (kalyna_ctx *ctx, int block_bits, int key_bits)
{
    int nb, nk, nr;
    if (block_bits == 128) {
        nb = 2;
        if      (key_bits == 128) { nk = 2; nr = 10; }
        else if (key_bits == 256) { nk = 4; nr = 14; }
        else                       return -1;
    } else if (block_bits == 256) {
        nb = 4;
        if      (key_bits == 256) { nk = 4; nr = 14; }
        else if (key_bits == 512) { nk = 8; nr = 18; }
        else                       return -1;
    } else if (block_bits == 512) {
        nb = 8;
        if      (key_bits == 512) { nk = 8; nr = 18; }
        else                       return -1;
    } else {
        return -1;
    }
    memset (ctx, 0, sizeof *ctx);
    ctx->nb = nb;
    ctx->nk = nk;
    ctx->nr = nr;
    return 0;
}

void kalyna_set_key (kalyna_ctx *ctx, const uint8_t *key)
{
    uint64_t k[KALYNA_MAX_NB * 2];
    for (int i = 0; i < ctx->nk; ++i) k[i] = load64 (key + i * 8);

    uint64_t kt[KALYNA_MAX_NB];
    key_expand_kt (ctx, k, kt);
    key_expand_even (ctx, k, kt);
    key_expand_odd (ctx);
}

void kalyna_encrypt (const kalyna_ctx *ctx_const, const uint8_t *in, uint8_t *out)
{
    /* The transformations need a non-const ctx for nb/nk lookups; round_keys never changes. */
    kalyna_ctx ctx = *ctx_const;
    uint64_t state[KALYNA_MAX_NB];
    for (int i = 0; i < ctx.nb; ++i) state[i] = load64 (in + i * 8);

    add_words (state, ctx.round_keys[0], ctx.nb);
    for (int r = 1; r < ctx.nr; ++r) {
        encipher_round (&ctx, state);
        xor_words (state, ctx.round_keys[r], ctx.nb);
    }
    encipher_round (&ctx, state);
    add_words (state, ctx.round_keys[ctx.nr], ctx.nb);

    for (int i = 0; i < ctx.nb; ++i) store64 (out + i * 8, state[i]);
}

void kalyna_decrypt (const kalyna_ctx *ctx_const, const uint8_t *in, uint8_t *out)
{
    kalyna_ctx ctx = *ctx_const;
    uint64_t state[KALYNA_MAX_NB];
    for (int i = 0; i < ctx.nb; ++i) state[i] = load64 (in + i * 8);

    sub_words (state, ctx.round_keys[ctx.nr], ctx.nb);
    for (int r = ctx.nr - 1; r > 0; --r) {
        decipher_round (&ctx, state);
        xor_words (state, ctx.round_keys[r], ctx.nb);
    }
    decipher_round (&ctx, state);
    sub_words (state, ctx.round_keys[0], ctx.nb);

    for (int i = 0; i < ctx.nb; ++i) store64 (out + i * 8, state[i]);
}
