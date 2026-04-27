/**
 * Author......: Alex Melan (A.K.A. Alex_Melan)
 * License.....: MIT
 *
 * Kalyna (DSTU 7624:2014) — encrypt-only OpenCL helpers used by the hashcat
 * Kalyna modes (m36000 .. m36400).
 *
 * The implementation is parameterised at compile time via three macros that
 * MUST be defined before this header is included:
 *
 *   KALYNA_NB  — number of 64-bit words in the cipher block (2, 4 or 8)
 *   KALYNA_NK  — number of 64-bit words in the key          (2, 4 or 8)
 *   KALYNA_NR  — number of rounds                           (10, 14 or 18)
 *
 * Valid (nb, nk, nr) tuples:
 *   (2, 2, 10), (2, 4, 14), (4, 4, 14), (4, 8, 18), (8, 8, 18)
 *
 * Conventions:
 *   - block / key are arrays of u32, little-endian
 *   - round_keys array has (KALYNA_NR + 1) * KALYNA_NB u64 words
 */

#ifndef INC_CIPHER_KALYNA_H
#define INC_CIPHER_KALYNA_H

#if !defined (KALYNA_NB) || !defined (KALYNA_NK) || !defined (KALYNA_NR)
#error "include inc_cipher_kalyna.cl: define KALYNA_NB, KALYNA_NK, KALYNA_NR first"
#endif

#define KALYNA_BLOCK_U32   (KALYNA_NB * 2)
#define KALYNA_BLOCK_BYTES (KALYNA_NB * 8)
#define KALYNA_KEY_BYTES   (KALYNA_NK * 8)
#define KALYNA_RK_WORDS    ((KALYNA_NR + 1) * KALYNA_NB)

#endif /* INC_CIPHER_KALYNA_H */
