/**
 * Author......: Alex Melan (A.K.A. Alex_Melan)
 * License.....: MIT
 *
 * Hashcat mode 36000 — Kalyna-128/128 KPA, attack-mode 1 (combinator).
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#define KALYNA_NB 2
#define KALYNA_NK 2
#define KALYNA_NR 10
#include M2S(INCLUDE_PATH/inc_cipher_kalyna.cl)
#endif

DECLSPEC void m36000_combine (PRIVATE_AS const u32 *pw_l, const u32 pw_l_len,
                              PRIVATE_AS const u32 *pw_r, const u32 pw_r_len,
                              PRIVATE_AS u32 *key)
{
  /* Build a 16-byte key from left || right candidates.
     For pw_min=pw_max=16 the combinator only feeds us pairs that sum to 16,
     but we still have to byte-align the right half. */
  u8 buf[16] = { 0 };

  const u32 ll = pw_l_len & 31;
  const u32 lr = pw_r_len & 31;

  for (u32 i = 0; i < ll && i < 16; ++i)
  {
    buf[i] = (u8) (pw_l[i / 4] >> ((i & 3) * 8));
  }
  for (u32 i = 0; i < lr && (ll + i) < 16; ++i)
  {
    buf[ll + i] = (u8) (pw_r[i / 4] >> ((i & 3) * 8));
  }

  for (int i = 0; i < 4; ++i)
  {
    key[i] = ((u32) buf[i * 4 + 0])
           | ((u32) buf[i * 4 + 1] <<  8)
           | ((u32) buf[i * 4 + 2] << 16)
           | ((u32) buf[i * 4 + 3] << 24);
  }
}

KERNEL_FQ KERNEL_FA void m36000_mxx (KERN_ATTR_BASIC ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  u32 pw_l[4];
  pw_l[0] = pws[gid].i[0];
  pw_l[1] = pws[gid].i[1];
  pw_l[2] = pws[gid].i[2];
  pw_l[3] = pws[gid].i[3];

  const u32 pw_l_len = pws[gid].pw_len;

  u32 salt_buf[4];
  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32 pw_r[4];
    pw_r[0] = combs_buf[il_pos].i[0];
    pw_r[1] = combs_buf[il_pos].i[1];
    pw_r[2] = combs_buf[il_pos].i[2];
    pw_r[3] = combs_buf[il_pos].i[3];

    const u32 pw_r_len = combs_buf[il_pos].pw_len;

    u32 key[4];
    m36000_combine (pw_l, pw_l_len, pw_r, pw_r_len, key);

    u64 rks[KALYNA_RK_WORDS];
    kalyna_set_key (rks, key);

    u32 ct[4];
    kalyna_encrypt (rks, salt_buf, ct);

    const u32 r0 = ct[0];
    const u32 r1 = ct[1];
    const u32 r2 = ct[2];
    const u32 r3 = ct[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m36000_sxx (KERN_ATTR_BASIC ())
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

  u32 pw_l[4];
  pw_l[0] = pws[gid].i[0];
  pw_l[1] = pws[gid].i[1];
  pw_l[2] = pws[gid].i[2];
  pw_l[3] = pws[gid].i[3];

  const u32 pw_l_len = pws[gid].pw_len;

  u32 salt_buf[4];
  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32 pw_r[4];
    pw_r[0] = combs_buf[il_pos].i[0];
    pw_r[1] = combs_buf[il_pos].i[1];
    pw_r[2] = combs_buf[il_pos].i[2];
    pw_r[3] = combs_buf[il_pos].i[3];

    const u32 pw_r_len = combs_buf[il_pos].pw_len;

    u32 key[4];
    m36000_combine (pw_l, pw_l_len, pw_r, pw_r_len, key);

    u64 rks[KALYNA_RK_WORDS];
    kalyna_set_key (rks, key);

    u32 ct[4];
    kalyna_encrypt (rks, salt_buf, ct);

    const u32 r0 = ct[0];
    const u32 r1 = ct[1];
    const u32 r2 = ct[2];
    const u32 r3 = ct[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
