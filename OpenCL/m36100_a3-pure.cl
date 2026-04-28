/**
 * Author......: Alex Melan (A.K.A. Alex_Melan)
 * License.....: MIT
 *
 * Hashcat mode 36100 — Kalyna-128/256 KPA, attack-mode 3 (mask brute force).
 *
 * Pure scalar (VECT_SIZE = 1) so the Kalyna routines, which work on u32, are
 * not asked to swallow a SIMD u32x lane.
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

KERNEL_FQ KERNEL_FA void m36100_mxx (KERN_ATTR_BASIC ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  u32 w[8];
  for (int i = 0; i < 8; ++i) w[i] = pws[gid].i[i];

  u32 salt_buf[4];
  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  const u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; ++il_pos)
  {
    const u32 w0r = bfs_buf[il_pos].i;
    const u32 w0  = w0l | w0r;

    u32 key[8];
    key[0] = w0;
    key[1] = w[1]; key[2] = w[2]; key[3] = w[3];
    key[4] = w[4]; key[5] = w[5]; key[6] = w[6]; key[7] = w[7];

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

  u32 w[8];
  for (int i = 0; i < 8; ++i) w[i] = pws[gid].i[i];

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

  const u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; ++il_pos)
  {
    const u32 w0r = bfs_buf[il_pos].i;
    const u32 w0  = w0l | w0r;

    u32 key[8];
    key[0] = w0;
    key[1] = w[1]; key[2] = w[2]; key[3] = w[3];
    key[4] = w[4]; key[5] = w[5]; key[6] = w[6]; key[7] = w[7];

    u64 rks[KALYNA_RK_WORDS];
    kalyna_set_key (rks, key);

    u32 ct[4];
    kalyna_encrypt (rks, salt_buf, ct);

    const u32 r0 = ct[0]; const u32 r1 = ct[1]; const u32 r2 = ct[2]; const u32 r3 = ct[3];
    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
