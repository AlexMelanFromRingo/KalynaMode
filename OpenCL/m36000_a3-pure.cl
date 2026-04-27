/**
 * Author......: Alex Melan (A.K.A. Alex_Melan)
 * License.....: MIT
 *
 * Hashcat mode 36000 — Kalyna-128/128 KPA, attack-mode 3 (mask brute force).
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#define KALYNA_NB 2
#define KALYNA_NK 2
#define KALYNA_NR 10
#include M2S(INCLUDE_PATH/inc_cipher_kalyna.cl)
#endif

KERNEL_FQ KERNEL_FA void m36000_mxx (KERN_ATTR_VECTOR ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  u32 w[4];
  w[0] = pws[gid].i[0];
  w[1] = pws[gid].i[1];
  w[2] = pws[gid].i[2];
  w[3] = pws[gid].i[3];

  u32 salt_buf[4];
  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  const u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];
    const u32x w0  = w0l | w0r;

    u32 key[4];
    key[0] = w0;
    key[1] = w[1];
    key[2] = w[2];
    key[3] = w[3];

    u64 rks[KALYNA_RK_WORDS];
    kalyna_set_key (rks, key);

    u32 ct[4];
    kalyna_encrypt (rks, salt_buf, ct);

    const u32x r0 = ct[0];
    const u32x r1 = ct[1];
    const u32x r2 = ct[2];
    const u32x r3 = ct[3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m36000_sxx (KERN_ATTR_VECTOR ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  u32 w[4];
  w[0] = pws[gid].i[0];
  w[1] = pws[gid].i[1];
  w[2] = pws[gid].i[2];
  w[3] = pws[gid].i[3];

  u32 salt_buf[4];
  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  const u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];
    const u32x w0  = w0l | w0r;

    u32 key[4];
    key[0] = w0;
    key[1] = w[1];
    key[2] = w[2];
    key[3] = w[3];

    u64 rks[KALYNA_RK_WORDS];
    kalyna_set_key (rks, key);

    u32 ct[4];
    kalyna_encrypt (rks, salt_buf, ct);

    const u32x r0 = ct[0];
    const u32x r1 = ct[1];
    const u32x r2 = ct[2];
    const u32x r3 = ct[3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
