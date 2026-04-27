# KalynaMode — Kalyna (DSTU 7624:2014) for hashcat

Adds a known‑plaintext attack mode for the Ukrainian state cipher
**Kalyna** (DSTU 7624:2014) to [hashcat](https://github.com/hashcat/hashcat).

* `-m 36000` — Kalyna‑128/128 (block 128 b, key 128 b, 10 rounds) — **fully implemented and tested**
* `-m 36100` — Kalyna‑128/256 (block 128 b, key 256 b, 14 rounds) — **fully implemented and tested**
* `-m 36200`, `-m 36300`, `-m 36400` — scaffolded (host reference works, kernels TODO; see *Roadmap*)

## What it does

Both implemented modes attack one Kalyna block ciphertext where both the
plaintext and the ciphertext are known and the password *is* the raw
Kalyna key:

```
encrypt(key = $pass, plaintext = $salt) == $digest
```

Hash format:

```
<ciphertext_hex>:<plaintext_hex>
```

Each half is exactly one Kalyna block written as hex. For Kalyna‑128
that is 32 hex chars (16 bytes). The candidate password is treated as
raw key bytes — 16 bytes for `m36000`, 32 bytes for `m36100`.

This is the same shape hashcat already uses for `-m 14000` (DES KPA) and
related "raw cipher KPA" modes.

## Quick start

```sh
# 1. Get hashcat
git clone --depth 1 https://github.com/hashcat/hashcat.git
cd hashcat

# 2. Drop in the Kalyna plugin
git clone --depth 1 https://github.com/AlexMelanFromRingo/KalynaMode.git /tmp/KalynaMode
/tmp/KalynaMode/apply.sh .

# 3. Build
make -j

# 4. Build the host‑side hash generator and self‑test
make -C /tmp/KalynaMode/tools test

# 5. Generate a hash and crack it
/tmp/KalynaMode/tools/kalyna_gen 128/128 "MyKalyna1234567!" \
    "0011223344556677aabbccddeeff0011" > /tmp/test.hash
echo "MyKalyna1234567!" > /tmp/test.dict
./hashcat -m 36000 -a 0 /tmp/test.hash /tmp/test.dict
```

## What lives where

```
src/modules/module_36000.c   - hashcat host‑side module (mode 36000)
src/modules/module_36100.c   - hashcat host‑side module (mode 36100)
OpenCL/inc_cipher_kalyna.h   - device‑side API
OpenCL/inc_cipher_kalyna.cl  - device‑side Kalyna implementation,
                                parameterised at compile time via
                                KALYNA_NB / KALYNA_NK / KALYNA_NR
OpenCL/m36000_a{0,1,3}-pure.cl  - kernels for attack modes 0/1/3
OpenCL/m36100_a{0,1,3}-pure.cl  - kernels for attack modes 0/1/3
tools/kalyna.{c,h}           - portable host reference for all five
                                DSTU variants (128/128 ... 512/512)
tools/kalyna_tables.h        - S‑box tables
tools/kalyna_gen.c           - hash generator + self‑test against the
                                published DSTU vectors
tools/kalyna128_kernel_check.c  - cross‑check that the GPU kernel
                                algorithm matches the reference
apply.sh                     - copies plugin files into a hashcat tree
```

## Self‑test

The host‑side reference reproduces every Kalyna ciphertext from the
DSTU 7624:2014 reference vectors:

```text
Kalyna-128/128 ct = 81bf1c7d779bac20e1c9ea39b4d2ad06
Kalyna-128/256 ct = 58ec3e091000158a1148f7166f334f14
Kalyna-256/256 ct = f66e3d570ec92135aedae323dcbd2a8ca03963ec206a0d5a88385c24617fd92c
Kalyna-256/512 ct = 606990e9e6b7b67a4bd6d893d72268b78e02c83c3cd7e102fd2e74a8fdfe5dd9
Kalyna-512/512 ct = 4a26e31b811c356aa61dd6ca0596231a67ba8354aa47f3a13e1deec320eb56b8
                    95d0f417175bab662fd6f134bb15c86ccb906a26856efeb7c5bc6472940dd9d9
```

Run `make -C tools test` to verify locally.

## Hashcat side benchmarks

On an RTX 4080 SUPER (`-m 36000`):

```
Speed.#01........:   232.6 MH/s (87.98ms) @ Accel:4 Loops:256 Thr:256 Vec:1
```

## Roadmap

`m36200` / `m36300` / `m36400` need a custom comparison path because
hashcat's stock `find_hash` / `COMPARE_*_SIMD` macros only diff the
first 4 u32 of the digest, which is fine for a 16‑byte ciphertext but
admits false positives for 32‑ or 64‑byte ciphertexts. The host
reference already produces correct ciphertexts for those variants;
adding the kernels just means writing an explicit full‑block compare
on top of the existing scaffolding.

## Licence

MIT. The S‑box tables and the algorithmic skeleton are taken from the
MIT‑licensed reference implementation by Ruslan Kiianchuk, Ruslan
Mordvinov and Roman Oliynykov
([rkiyanchuk/kalyna](https://github.com/rkiyanchuk/kalyna)).
