/**
 * Author......: Alex Melan (A.K.A. Alex_Melan)
 * License.....: MIT
 *
 * Hashcat mode 36100 — Kalyna-128/256 KPA, attack-mode 1 (combinator).
 */

//#define NEW_SIMD_CODE

#define KALYNA_NB 2
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

DECLSPEC void m36100_combine (PRIVATE_AS const u32 *pw_l, const u32 pw_l_len,
                              PRIVATE_AS const u32 *pw_r, const u32 pw_r_len,
                              PRIVATE_AS u32 *key)
{
  u8 buf[32] = { 0 };

  const u32 ll = pw_l_len & 63;
  const u32 lr = pw_r_len & 63;

  for (u32 i = 0; i < ll && i < 32; ++i)
    buf[i] = (u8) (pw_l[i / 4] >> ((i & 3) * 8));
  for (u32 i = 0; i < lr && (ll + i) < 32; ++i)
    buf[ll + i] = (u8) (pw_r[i / 4] >> ((i & 3) * 8));

  for (int i = 0; i < 8; ++i)
  {
    key[i] = ((u32) buf[i * 4 + 0])
           | ((u32) buf[i * 4 + 1] <<  8)
           | ((u32) buf[i * 4 + 2] << 16)
           | ((u32) buf[i * 4 + 3] << 24);
  }
}

KERNEL_FQ KERNEL_FA void m36100_mxx (KERN_ATTR_BASIC ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  u32 pw_l[8];
  for (int i = 0; i < 8; ++i) pw_l[i] = pws[gid].i[i];
  const u32 pw_l_len = pws[gid].pw_len;

  u32 salt_buf[4];
  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32 pw_r[8];
    for (int i = 0; i < 8; ++i) pw_r[i] = combs_buf[il_pos].i[i];
    const u32 pw_r_len = combs_buf[il_pos].pw_len;

    u32 key[8];
    m36100_combine (pw_l, pw_l_len, pw_r, pw_r_len, key);

    u64 rks[KALYNA_RK_WORDS];
    kalyna_set_key (rks, key);

    u32 ct[4];
    kalyna_encrypt (rks, salt_buf, ct);

    const u32 r0 = ct[0]; const u32 r1 = ct[1]; const u32 r2 = ct[2]; const u32 r3 = ct[3];
    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m36100_sxx (KERN_ATTR_BASIC ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  u32 pw_l[8];
  for (int i = 0; i < 8; ++i) pw_l[i] = pws[gid].i[i];
  const u32 pw_l_len = pws[gid].pw_len;

  u32 salt_buf[4];
  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32 pw_r[8];
    for (int i = 0; i < 8; ++i) pw_r[i] = combs_buf[il_pos].i[i];
    const u32 pw_r_len = combs_buf[il_pos].pw_len;

    u32 key[8];
    m36100_combine (pw_l, pw_l_len, pw_r, pw_r_len, key);

    u64 rks[KALYNA_RK_WORDS];
    kalyna_set_key (rks, key);

    u32 ct[4];
    kalyna_encrypt (rks, salt_buf, ct);

    const u32 r0 = ct[0]; const u32 r1 = ct[1]; const u32 r2 = ct[2]; const u32 r3 = ct[3];
    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
