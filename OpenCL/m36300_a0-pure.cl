/**
 * Author......: Alex Melan (A.K.A. Alex_Melan)
 * License.....: MIT
 *
 * Hashcat mode 36300 — Kalyna-256/512 KPA, attack-mode 0 (dictionary + rules).
 *
 * Block 32 B (8 u32) so the comparison uses a bitmap pre-filter on the first
 * 4 u32 plus an explicit verify of the remaining 4 u32 against the matched
 * digest.
 */

//#define NEW_SIMD_CODE

#define KALYNA_NB 4
#define KALYNA_NK 8
#define KALYNA_NR 18

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
#define KALYNA_KEY_U32   16

KERNEL_FQ KERNEL_FA void m36300_mxx (KERN_ATTR_RULES ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  /* 64-byte key — won't fit into the 8-u32 buffer apply_rules expects, so we
     bypass rule application and use the raw password (rules are not useful for
     a 64-byte fixed-size raw-key attack anyway). */
  u32 key[KALYNA_KEY_U32];
  for (int i = 0; i < KALYNA_KEY_U32; ++i) key[i] = pws[gid].i[i];

  u32 salt_buf[KALYNA_BLOCK_U32];
  for (int i = 0; i < KALYNA_BLOCK_U32; ++i) salt_buf[i] = salt_bufs[SALT_POS_HOST].salt_buf[i];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u64 rks[KALYNA_RK_WORDS];
    kalyna_set_key (rks, key);

    u32 ct[KALYNA_BLOCK_U32];
    kalyna_encrypt (rks, salt_buf, ct);

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

KERNEL_FQ KERNEL_FA void m36300_sxx (KERN_ATTR_RULES ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  u32 key[KALYNA_KEY_U32];
  for (int i = 0; i < KALYNA_KEY_U32; ++i) key[i] = pws[gid].i[i];

  u32 salt_buf[KALYNA_BLOCK_U32];
  for (int i = 0; i < KALYNA_BLOCK_U32; ++i) salt_buf[i] = salt_bufs[SALT_POS_HOST].salt_buf[i];

  u32 search[KALYNA_BLOCK_U32];
  for (int i = 0; i < KALYNA_BLOCK_U32; ++i) search[i] = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[i];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u64 rks[KALYNA_RK_WORDS];
    kalyna_set_key (rks, key);

    u32 ct[KALYNA_BLOCK_U32];
    kalyna_encrypt (rks, salt_buf, ct);

    int match = 1;
    for (int i = 0; i < KALYNA_BLOCK_U32; ++i) if (ct[i] != search[i]) { match = 0; break; }
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
