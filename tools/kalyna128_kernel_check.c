/*
 * Cross-check tool: re-implements Kalyna-128/128 *exactly* as in
 * OpenCL/inc_cipher_kalyna.cl (branchless GF mul, byte-wise MixColumns
 * unrolled) and verifies output against the reference (kalyna128.c).
 *
 * Build:   cc -O2 kalyna128_kernel_check.c kalyna128.c -o kalyna_kernel_check
 * Run:     ./kalyna_kernel_check
 */

#include "kalyna128.h"
#include "kalyna_tables.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

#define KAL_M2(x) ((u8) (((u32)(x) << 1) ^ (((u32) 0u - ((u32)(x) >> 7)) & 0x1du)))

static u64 sub_bytes_word (const u64 v)
{
    return ((u64) sboxes_enc[0][(u32)(v >>  0) & 0xff])       |
           ((u64) sboxes_enc[1][(u32)(v >>  8) & 0xff] <<  8) |
           ((u64) sboxes_enc[2][(u32)(v >> 16) & 0xff] << 16) |
           ((u64) sboxes_enc[3][(u32)(v >> 24) & 0xff] << 24) |
           ((u64) sboxes_enc[0][(u32)(v >> 32) & 0xff] << 32) |
           ((u64) sboxes_enc[1][(u32)(v >> 40) & 0xff] << 40) |
           ((u64) sboxes_enc[2][(u32)(v >> 48) & 0xff] << 48) |
           ((u64) sboxes_enc[3][(u32)(v >> 56) & 0xff] << 56);
}

static void sub_bytes (u64 *s) { s[0] = sub_bytes_word (s[0]); s[1] = sub_bytes_word (s[1]); }

static void shift_rows (u64 *s)
{
    const u64 lo0 = s[0] & 0x00000000ffffffffULL;
    const u64 hi0 = s[0] & 0xffffffff00000000ULL;
    const u64 lo1 = s[1] & 0x00000000ffffffffULL;
    const u64 hi1 = s[1] & 0xffffffff00000000ULL;
    s[0] = lo0 | hi1;
    s[1] = lo1 | hi0;
}

static u64 mix_one_column (const u64 v)
{
    const u8 b0 = (u8)(v >>  0);
    const u8 b1 = (u8)(v >>  8);
    const u8 b2 = (u8)(v >> 16);
    const u8 b3 = (u8)(v >> 24);
    const u8 b4 = (u8)(v >> 32);
    const u8 b5 = (u8)(v >> 40);
    const u8 b6 = (u8)(v >> 48);
    const u8 b7 = (u8)(v >> 56);

    const u8 b0_2 = KAL_M2(b0); const u8 b0_4 = KAL_M2(b0_2); const u8 b0_8 = KAL_M2(b0_4);
    const u8 b1_2 = KAL_M2(b1); const u8 b1_4 = KAL_M2(b1_2); const u8 b1_8 = KAL_M2(b1_4);
    const u8 b2_2 = KAL_M2(b2); const u8 b2_4 = KAL_M2(b2_2); const u8 b2_8 = KAL_M2(b2_4);
    const u8 b3_2 = KAL_M2(b3); const u8 b3_4 = KAL_M2(b3_2); const u8 b3_8 = KAL_M2(b3_4);
    const u8 b4_2 = KAL_M2(b4); const u8 b4_4 = KAL_M2(b4_2); const u8 b4_8 = KAL_M2(b4_4);
    const u8 b5_2 = KAL_M2(b5); const u8 b5_4 = KAL_M2(b5_2); const u8 b5_8 = KAL_M2(b5_4);
    const u8 b6_2 = KAL_M2(b6); const u8 b6_4 = KAL_M2(b6_2); const u8 b6_8 = KAL_M2(b6_4);
    const u8 b7_2 = KAL_M2(b7); const u8 b7_4 = KAL_M2(b7_2); const u8 b7_8 = KAL_M2(b7_4);

    #define KM5(B) ((u8)(B##_4 ^ B))
    #define KM6(B) ((u8)(B##_4 ^ B##_2))
    #define KM7(B) ((u8)(B##_4 ^ B##_2 ^ B))

    const u8 o0 = (u8)(b0      ^ b1      ^ KM5(b2) ^ b3      ^ b4_8    ^ KM6(b5) ^ KM7(b6) ^ b7_4);
    const u8 o1 = (u8)(b0_4    ^ b1      ^ b2      ^ KM5(b3) ^ b4      ^ b5_8    ^ KM6(b6) ^ KM7(b7));
    const u8 o2 = (u8)(KM7(b0) ^ b1_4    ^ b2      ^ b3      ^ KM5(b4) ^ b5      ^ b6_8    ^ KM6(b7));
    const u8 o3 = (u8)(KM6(b0) ^ KM7(b1) ^ b2_4    ^ b3      ^ b4      ^ KM5(b5) ^ b6      ^ b7_8);
    const u8 o4 = (u8)(b0_8    ^ KM6(b1) ^ KM7(b2) ^ b3_4    ^ b4      ^ b5      ^ KM5(b6) ^ b7);
    const u8 o5 = (u8)(b0      ^ b1_8    ^ KM6(b2) ^ KM7(b3) ^ b4_4    ^ b5      ^ b6      ^ KM5(b7));
    const u8 o6 = (u8)(KM5(b0) ^ b1      ^ b2_8    ^ KM6(b3) ^ KM7(b4) ^ b5_4    ^ b6      ^ b7);
    const u8 o7 = (u8)(b0      ^ KM5(b1) ^ b2      ^ b3_8    ^ KM6(b4) ^ KM7(b5) ^ b6_4    ^ b7);

    #undef KM5
    #undef KM6
    #undef KM7

    return ((u64)o0)        | ((u64)o1 <<  8) | ((u64)o2 << 16) | ((u64)o3 << 24)
         | ((u64)o4 << 32)  | ((u64)o5 << 40) | ((u64)o6 << 48) | ((u64)o7 << 56);
}

static void mix_columns (u64 *s) { s[0] = mix_one_column (s[0]); s[1] = mix_one_column (s[1]); }

static void encipher_round (u64 *s) { sub_bytes (s); shift_rows (s); mix_columns (s); }

static void rotate_left_7 (u64 *s)
{
    const u64 a = s[0];
    const u64 b = s[1];
    s[0] = (a >> 56) | (b << 8);
    s[1] = (b >> 56) | (a << 8);
}

static void key_expand (const u32 key[4], u64 rks[22])
{
    const u64 k0 = ((u64)key[0]) | (((u64)key[1]) << 32);
    const u64 k1 = ((u64)key[2]) | (((u64)key[3]) << 32);

    u64 state[2];
    state[0] = (u64)5;
    state[1] = 0;
    state[0] += k0; state[1] += k1;
    encipher_round (state);
    state[0] ^= k0; state[1] ^= k1;
    encipher_round (state);
    state[0] += k0; state[1] += k1;
    encipher_round (state);

    const u64 kt0 = state[0];
    const u64 kt1 = state[1];

    u64 init0 = k0, init1 = k1;
    u64 tmv0 = 0x0001000100010001ULL;
    u64 tmv1 = 0x0001000100010001ULL;

    for (int round = 0; ; ) {
        u64 ktr0 = kt0 + tmv0;
        u64 ktr1 = kt1 + tmv1;
        state[0] = init0 + ktr0;
        state[1] = init1 + ktr1;
        encipher_round (state);
        state[0] ^= ktr0; state[1] ^= ktr1;
        encipher_round (state);
        state[0] += ktr0; state[1] += ktr1;

        rks[round * 2 + 0] = state[0];
        rks[round * 2 + 1] = state[1];

        if (round == 10) break;
        round += 2;
        tmv0 <<= 1; tmv1 <<= 1;
        const u64 t = init0; init0 = init1; init1 = t;
    }

    for (int i = 1; i < 10; i += 2) {
        u64 tmp[2];
        tmp[0] = rks[(i - 1) * 2 + 0];
        tmp[1] = rks[(i - 1) * 2 + 1];
        rotate_left_7 (tmp);
        rks[i * 2 + 0] = tmp[0];
        rks[i * 2 + 1] = tmp[1];
    }
}

static void encrypt_blk (const u64 rks[22], const u32 in[4], u32 out[4])
{
    u64 s0 = ((u64)in[0]) | (((u64)in[1]) << 32);
    u64 s1 = ((u64)in[2]) | (((u64)in[3]) << 32);
    u64 state[2];
    state[0] = s0 + rks[0];
    state[1] = s1 + rks[1];
    for (int r = 1; r < 10; ++r) {
        encipher_round (state);
        state[0] ^= rks[r * 2 + 0];
        state[1] ^= rks[r * 2 + 1];
    }
    encipher_round (state);
    state[0] += rks[10 * 2 + 0];
    state[1] += rks[10 * 2 + 1];
    out[0] = (u32)(state[0] >>  0);
    out[1] = (u32)(state[0] >> 32);
    out[2] = (u32)(state[1] >>  0);
    out[3] = (u32)(state[1] >> 32);
}

static void hex2bytes (const char *s, u8 *out, int n)
{
    for (int i = 0; i < n; ++i) {
        unsigned int v;
        sscanf (s + i * 2, "%2x", &v);
        out[i] = (u8) v;
    }
}

int main (void)
{
    /* Reference test vector */
    u8 key_b[16], pt_b[16], expected[16] = {0x81,0xbf,0x1c,0x7d,0x77,0x9b,0xac,0x20,0xe1,0xc9,0xea,0x39,0xb4,0xd2,0xad,0x06};
    hex2bytes ("000102030405060708090a0b0c0d0e0f", key_b, 16);
    hex2bytes ("101112131415161718191a1b1c1d1e1f", pt_b, 16);

    /* Through reference */
    kalyna128_ctx ctx;
    kalyna128_set_key (&ctx, key_b);
    u8 ct_ref[16];
    kalyna128_encrypt (&ctx, pt_b, ct_ref);
    if (memcmp (ct_ref, expected, 16) != 0) {
        fprintf (stderr, "reference FAILED\n");
        return 1;
    }
    printf ("reference impl OK\n");

    /* Through optimized (kernel-style) impl */
    u32 key32[4], pt32[4], ct32[4];
    for (int i = 0; i < 4; ++i) {
        key32[i] = (u32)key_b[i*4] | ((u32)key_b[i*4+1] << 8) | ((u32)key_b[i*4+2] << 16) | ((u32)key_b[i*4+3] << 24);
        pt32[i]  = (u32)pt_b[i*4]  | ((u32)pt_b[i*4+1]  << 8) | ((u32)pt_b[i*4+2]  << 16) | ((u32)pt_b[i*4+3]  << 24);
    }
    u64 rks[22];
    key_expand (key32, rks);
    encrypt_blk (rks, pt32, ct32);

    u8 ct_opt[16];
    for (int i = 0; i < 4; ++i) {
        ct_opt[i*4 + 0] = (u8)(ct32[i] >>  0);
        ct_opt[i*4 + 1] = (u8)(ct32[i] >>  8);
        ct_opt[i*4 + 2] = (u8)(ct32[i] >> 16);
        ct_opt[i*4 + 3] = (u8)(ct32[i] >> 24);
    }
    if (memcmp (ct_opt, expected, 16) != 0) {
        fprintf (stderr, "kernel-style impl FAILED\n");
        for (int i = 0; i < 16; ++i) fprintf (stderr, "%02x", ct_opt[i]);
        fprintf (stderr, "\n");
        return 1;
    }
    printf ("kernel-style impl OK\n");

    /* Test the m36000 selftest vector too */
    u8 pw[16] = "hashcat36000kaly";
    hex2bytes ("101112131415161718191a1b1c1d1e1f", pt_b, 16);
    u8 expected2[16] = {0xfb,0x20,0xd6,0x5f,0x52,0x5b,0x4e,0xd3,0x55,0xb6,0xd4,0x4c,0xb5,0xc8,0x0d,0xd0};

    for (int i = 0; i < 4; ++i) {
        key32[i] = (u32)pw[i*4] | ((u32)pw[i*4+1] << 8) | ((u32)pw[i*4+2] << 16) | ((u32)pw[i*4+3] << 24);
        pt32[i]  = (u32)pt_b[i*4]  | ((u32)pt_b[i*4+1]  << 8) | ((u32)pt_b[i*4+2]  << 16) | ((u32)pt_b[i*4+3]  << 24);
    }
    key_expand (key32, rks);
    encrypt_blk (rks, pt32, ct32);
    for (int i = 0; i < 4; ++i) {
        ct_opt[i*4 + 0] = (u8)(ct32[i] >>  0);
        ct_opt[i*4 + 1] = (u8)(ct32[i] >>  8);
        ct_opt[i*4 + 2] = (u8)(ct32[i] >> 16);
        ct_opt[i*4 + 3] = (u8)(ct32[i] >> 24);
    }
    if (memcmp (ct_opt, expected2, 16) != 0) {
        fprintf (stderr, "selftest m36000 vector FAILED\n");
        for (int i = 0; i < 16; ++i) fprintf (stderr, "%02x", ct_opt[i]);
        fprintf (stderr, "\n");
        return 1;
    }
    printf ("m36000 selftest vector OK\n");

    return 0;
}
