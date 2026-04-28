/**
 * Author......: Alex Melan (A.K.A. Alex_Melan)
 * License.....: MIT
 *
 * Hashcat mode 36200 — Kalyna-256/256 KPA, attack-mode 0 (dictionary + rules).
 *
 * Block is 32 B (8 u32) so we cannot use COMPARE_*_SCALAR directly because
 * those only diff 4 u32. We do a bitmap pre-filter on the first 4 u32 with
 * `check () + find_hash ()` and then verify the remaining 4 u32 against the
 * matched digest before calling mark_hash.
 */

//#define NEW_SIMD_CODE

#define KALYNA_NB 4
#define KALYNA_NK 4
#define KALYNA_NR 14

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_cipher_kalyna.cl)
#endif

#define KALYNA_BLOCK_U32 8

KERNEL_FQ KERNEL_FA void m36200_mxx (KERN_ATTR_RULES ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  u32 pw_buf0[4]; u32 pw_buf1[4];
  pw_buf0[0] = pws[gid].i[0]; pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2]; pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4]; pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6]; pw_buf1[3] = pws[gid].i[7];
  const u32 pw_len = pws[gid].pw_len;

  u32 salt_buf[8];
  for (int i = 0; i < 8; ++i) salt_buf[i] = salt_bufs[SALT_POS_HOST].salt_buf[i];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32 w0[4] = {0}; u32 w1[4] = {0}; u32 w2[4] = {0}; u32 w3[4] = {0};
    apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    u32 key[8];
    key[0] = w0[0]; key[1] = w0[1]; key[2] = w0[2]; key[3] = w0[3];
    key[4] = w1[0]; key[5] = w1[1]; key[6] = w1[2]; key[7] = w1[3];

    u64 rks[KALYNA_RK_WORDS];
    kalyna_set_key (rks, key);

    u32 ct[KALYNA_BLOCK_U32];
    kalyna_encrypt (rks, salt_buf, ct);

    /* Bitmap filter on first 4 u32, then verify the remaining 4 against the
       matched digest before marking the hash. */
    const u32 digest_tp0[4] = { ct[0], ct[1], ct[2], ct[3] };
    if (check (digest_tp0,
               bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,
               bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,
               BITMAP_MASK, BITMAP_SHIFT1, BITMAP_SHIFT2))
    {
      int digest_pos = find_hash (digest_tp0, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]);
      if (digest_pos != -1)
      {
        const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;
        const u32 d4 = digests_buf[final_hash_pos].digest_buf[4];
        const u32 d5 = digests_buf[final_hash_pos].digest_buf[5];
        const u32 d6 = digests_buf[final_hash_pos].digest_buf[6];
        const u32 d7 = digests_buf[final_hash_pos].digest_buf[7];
        if (ct[4] == d4 && ct[5] == d5 && ct[6] == d6 && ct[7] == d7)
        {
          if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)
          {
            mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, gid, il_pos, 0, 0);
          }
        }
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m36200_sxx (KERN_ATTR_RULES ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  u32 pw_buf0[4]; u32 pw_buf1[4];
  pw_buf0[0] = pws[gid].i[0]; pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2]; pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4]; pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6]; pw_buf1[3] = pws[gid].i[7];
  const u32 pw_len = pws[gid].pw_len;

  u32 salt_buf[8];
  for (int i = 0; i < 8; ++i) salt_buf[i] = salt_bufs[SALT_POS_HOST].salt_buf[i];

  /* Single-hash search vector covers the full 32-byte digest. */
  u32 search[8];
  for (int i = 0; i < 8; ++i) search[i] = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[i];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32 w0[4] = {0}; u32 w1[4] = {0}; u32 w2[4] = {0}; u32 w3[4] = {0};
    apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    u32 key[8];
    key[0] = w0[0]; key[1] = w0[1]; key[2] = w0[2]; key[3] = w0[3];
    key[4] = w1[0]; key[5] = w1[1]; key[6] = w1[2]; key[7] = w1[3];

    u64 rks[KALYNA_RK_WORDS];
    kalyna_set_key (rks, key);

    u32 ct[KALYNA_BLOCK_U32];
    kalyna_encrypt (rks, salt_buf, ct);

    int match = 1;
    for (int i = 0; i < 8; ++i) if (ct[i] != search[i]) { match = 0; break; }
    if (match)
    {
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;
      if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos, 0, 0);
      }
    }
  }
}
