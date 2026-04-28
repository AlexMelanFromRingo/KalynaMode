/**
 * Author......: Alex Melan (A.K.A. Alex_Melan)
 * License.....: MIT
 *
 * Hashcat mode 36200 — Kalyna-256/256 KPA, attack-mode 3 (mask brute force).
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
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_cipher_kalyna.cl)
#endif

#define KALYNA_BLOCK_U32 8

KERNEL_FQ KERNEL_FA void m36200_mxx (KERN_ATTR_BASIC ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  u32 w[8];
  for (int i = 0; i < 8; ++i) w[i] = pws[gid].i[i];

  u32 salt_buf[8];
  for (int i = 0; i < 8; ++i) salt_buf[i] = salt_bufs[SALT_POS_HOST].salt_buf[i];

  const u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; ++il_pos)
  {
    const u32 w0r = bfs_buf[il_pos].i;
    const u32 w0  = w0l | w0r;

    u32 key[8];
    key[0] = w0;
    for (int i = 1; i < 8; ++i) key[i] = w[i];

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

KERNEL_FQ KERNEL_FA void m36200_sxx (KERN_ATTR_BASIC ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  u32 w[8];
  for (int i = 0; i < 8; ++i) w[i] = pws[gid].i[i];

  u32 salt_buf[8];
  for (int i = 0; i < 8; ++i) salt_buf[i] = salt_bufs[SALT_POS_HOST].salt_buf[i];

  u32 search[8];
  for (int i = 0; i < 8; ++i) search[i] = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[i];

  const u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; ++il_pos)
  {
    const u32 w0r = bfs_buf[il_pos].i;
    const u32 w0  = w0l | w0r;

    u32 key[8];
    key[0] = w0;
    for (int i = 1; i < 8; ++i) key[i] = w[i];

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
