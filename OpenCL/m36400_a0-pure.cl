/**
 * Author......: Alex Melan (A.K.A. Alex_Melan)
 * License.....: MIT
 *
 * Hashcat mode 36400 — Kalyna-512/512 KPA, attack-mode 0 (dictionary).
 *
 * 64-byte block + 64-byte key. The full ciphertext is 16 u32; we bitmap-filter
 * on the first 4 u32 and explicitly verify the remaining 12 against the
 * matched digest before calling mark_hash.
 */

//#define NEW_SIMD_CODE

#define KALYNA_NB 8
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

#define KALYNA_BLOCK_U32 16
#define KALYNA_KEY_U32   16

DECLSPEC int kalyna_verify_tail (PRIVATE_AS const u32 *ct,
                                 GLOBAL_AS const digest_t *d)
{
  for (int i = 4; i < KALYNA_BLOCK_U32; ++i)
  {
    if (ct[i] != d->digest_buf[i]) return 0;
  }
  return 1;
}

KERNEL_FQ KERNEL_FA void m36400_mxx (KERN_ATTR_RULES ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  /* Skip rules — we already exhaust the keyspace via mask attacks for fixed-
     size raw-key modes; rules don't extend usefully past 32 bytes anyway. */
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
        if (kalyna_verify_tail (ct, &digests_buf[final_hash_pos]))
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

KERNEL_FQ KERNEL_FA void m36400_sxx (KERN_ATTR_RULES ())
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
