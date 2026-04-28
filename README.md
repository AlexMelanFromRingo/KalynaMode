# KalynaMode — Kalyna (DSTU 7624:2014) for hashcat

Adds known‑plaintext attack modes for the Ukrainian state cipher
**Kalyna** (DSTU 7624:2014) to [hashcat](https://github.com/hashcat/hashcat).

| Mode      | Variant       | Block | Key  | Rounds | Status |
|-----------|---------------|-------|------|--------|--------|
| `-m 36000`| Kalyna‑128/128| 128 b | 128 b| 10     | ✅ end‑to‑end (CUDA + PoCL) |
| `-m 36100`| Kalyna‑128/256| 128 b | 256 b| 14     | ✅ end‑to‑end (CUDA + PoCL¹) |
| `-m 36200`| Kalyna‑256/256| 256 b | 256 b| 14     | ✅ end‑to‑end (CUDA) |
| `-m 36300`| Kalyna‑256/512| 256 b | 512 b| 18     | ✅ end‑to‑end (CUDA) |
| `-m 36400`| Kalyna‑512/512| 512 b | 512 b| 18     | ✅ end‑to‑end (CUDA) |

¹ On PoCL CPU `m36100` cracks correctly with `--self-test-disable`. The
explicit OpenCL self‑test step there is a false positive — even a stub
kernel that emits the expected digest fails the same self‑test, so the
issue is in PoCL's selftest pipeline rather than in this plugin.

## What it does

For every mode, the cracker tests:

```
encrypt(key = $pass, plaintext = $salt) == $digest
```

Hash format:

```
<ciphertext_hex>:<plaintext_hex>
```

Each half is exactly one Kalyna block written as hex. The candidate
password is treated as raw key bytes — the password length must equal
the variant's key size in bytes (16, 32 or 64). The format is the same
shape hashcat already uses for `-m 14000` (DES KPA).

## Quick start

```sh
# 1. Get hashcat
git clone --depth 1 https://github.com/hashcat/hashcat.git
cd hashcat

# 2. Drop in the Kalyna plugin
git clone --depth 1 https://github.com/AlexMelanFromRingo/KalynaMode.git /tmp/KalynaMode
/tmp/KalynaMode/apply.sh .

# 3. Build hashcat
make -j

# 4. Build the host-side hash generator and run its self-test
make -C /tmp/KalynaMode/tools test

# 5. Generate a hash and crack it (any of the five variants)
/tmp/KalynaMode/tools/kalyna_gen 128/128 "MyKalyna1234567!" \
    "0011223344556677aabbccddeeff0011" > /tmp/k.hash
echo "MyKalyna1234567!" > /tmp/k.dict
./hashcat -m 36000 -a 0 /tmp/k.hash /tmp/k.dict

# 32-byte key:
/tmp/KalynaMode/tools/kalyna_gen 256/256 "test123testtesttesttesttesttest!" \
    "00112233445566778899aabbccddeeff112233445566778899aabbccddeeff00" > /tmp/k.hash
echo "test123testtesttesttesttesttest!" > /tmp/k.dict
./hashcat -m 36200 -a 0 /tmp/k.hash /tmp/k.dict
```

## Generating hashes

`tools/kalyna_gen` takes a `<block_bits>/<key_bits>` variant tag, a
password, and an optional plaintext (random if omitted):

```sh
./kalyna_gen 128/128 "<16-byte pw>" [<32-hex pt>]
./kalyna_gen 128/256 "<32-byte pw>" [<32-hex pt>]
./kalyna_gen 256/256 "<32-byte pw>" [<64-hex pt>]
./kalyna_gen 256/512 "<64-byte pw>" [<64-hex pt>]
./kalyna_gen 512/512 "<64-byte pw>" [<128-hex pt>]
```

Or `--hex` for raw key bytes:

```sh
./kalyna_gen --hex 128/128 <32-hex-key> <32-hex-pt>
```

## Layout

```
src/modules/module_36000.c   - Kalyna-128/128 module
src/modules/module_36100.c   - Kalyna-128/256 module
src/modules/module_36200.c   - Kalyna-256/256 module
src/modules/module_36300.c   - Kalyna-256/512 module
src/modules/module_36400.c   - Kalyna-512/512 module

OpenCL/inc_cipher_kalyna.h   - device-side public API
OpenCL/inc_cipher_kalyna.cl  - device-side Kalyna (KALYNA_NB / NK / NR
                                are compile-time parameters set by each
                                kernel)
OpenCL/m360{00,100,200,300,400}_a{0,3}-pure.cl  - kernels
OpenCL/m360{00,100,200}_a1-pure.cl              - combinator kernels
                                                  for the small-key modes

tools/kalyna.{c,h}           - portable host reference for all five
                                DSTU variants
tools/kalyna_tables.h        - S-box tables
tools/kalyna_gen.c           - hash generator + self-test
tools/kalyna128_kernel_check.c - cross-checks the device-side
                                  Kalyna-128/128 algebra against the
                                  reference implementation

apply.sh                     - copies plugin files into a hashcat tree
```

## Self-test

The host-side reference matches every Kalyna ciphertext from the DSTU
reference vectors:

```text
Kalyna-128/128 ct = 81bf1c7d779bac20e1c9ea39b4d2ad06
Kalyna-128/256 ct = 58ec3e091000158a1148f7166f334f14
Kalyna-256/256 ct = f66e3d570ec92135aedae323dcbd2a8ca03963ec206a0d5a88385c24617fd92c
Kalyna-256/512 ct = 606990e9e6b7b67a4bd6d893d72268b78e02c83c3cd7e102fd2e74a8fdfe5dd9
Kalyna-512/512 ct = 4a26e31b811c356aa61dd6ca0596231a67ba8354aa47f3a13e1deec320eb56b8
                    95d0f417175bab662fd6f134bb15c86ccb906a26856efeb7c5bc6472940dd9d9
```

Run `make -C tools test` to verify locally.

## Design notes

The device-side implementation lives in a single
`inc_cipher_kalyna.cl`, parameterised at compile time via
`KALYNA_NB`/`KALYNA_NK`/`KALYNA_NR`. Each `m36X00_*-pure.cl` kernel
file `#define`s those macros and includes the inc; the JIT compiler
unrolls the resulting fixed-size loops.

For 256‑ and 512‑bit blocks the ciphertext is bigger than the 16 bytes
hashcat's `find_hash`/`COMPARE_*` macros compare. The `_mxx`
multi-hash kernels still bitmap-filter on the first 4 u32 to keep the
fast path, then explicitly verify the remaining ciphertext words
against the matched digest before calling `mark_hash`. The `_sxx`
single-hash kernels diff the entire ciphertext directly.

## Known issues

* PoCL CPU may emit a noisy `OpenCL kernel self-test failed` warning for
  `m36100`. Cracking itself works correctly with `--self-test-disable`.
* No combinator (`-a 1`) kernels for `m36300` / `m36400` (combinators
  on raw 64‑byte keys are not a typical use case).

## Licence

MIT. The S‑box tables and the algorithmic skeleton are taken from the
MIT‑licensed reference implementation by Ruslan Kiianchuk, Ruslan
Mordvinov and Roman Oliynykov
([rkiyanchuk/kalyna](https://github.com/rkiyanchuk/kalyna)).
