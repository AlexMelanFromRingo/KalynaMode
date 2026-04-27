# Install KalynaMode into a hashcat tree

## Prerequisites

* A clone of `hashcat` (https://github.com/hashcat/hashcat) — any commit
  on master at or after the 7.x module-interface revision (this plugin
  was developed against `MODULE_INTERFACE_VERSION_CURRENT == 700`).
* GCC, GNU make, the usual hashcat build dependencies — see
  `BUILD.md` in the hashcat checkout.
* For the hash generator self-test: any C99 compiler.

## Drop-in install

```sh
# from the KalynaMode checkout
./apply.sh /path/to/hashcat
```

The script copies:

* `src/modules/module_36000.c`            → `<hashcat>/src/modules/`
* `src/modules/module_36100.c`            → `<hashcat>/src/modules/`
* `OpenCL/inc_cipher_kalyna.{h,cl}`       → `<hashcat>/OpenCL/`
* `OpenCL/m36000_a{0,1,3}-pure.cl`        → `<hashcat>/OpenCL/`
* `OpenCL/m36100_a{0,1,3}-pure.cl`        → `<hashcat>/OpenCL/`

Hashcat's Makefile auto-discovers `src/modules/module_*.c`, so just
re-run `make -j` and `module_36000.so` / `module_36100.so` will
appear under `modules/`.

## Verifying the install

1. Build the host-side reference and run the self-test:

   ```sh
   make -C tools test
   ```

   You should see ciphertexts that match the DSTU 7624:2014 vectors for
   every variant.

2. Hashcat self-test:

   ```sh
   <hashcat>/hashcat -m 36000 -b --runtime=8 --force
   <hashcat>/hashcat -m 36100 -b --runtime=8 --force
   ```

3. End-to-end cracking smoke test:

   ```sh
   ./tools/kalyna_gen 128/128 "MyKalyna1234567!" \
       "0011223344556677aabbccddeeff0011" > /tmp/kal.hash
   echo "MyKalyna1234567!" > /tmp/kal.dict
   <hashcat>/hashcat -m 36000 -a 0 /tmp/kal.hash /tmp/kal.dict
   ```

   Expected: `Status: Cracked`.

## Known issues

* On some PoCL CPU runtimes the explicit OpenCL kernel self-test for
  `-m 36100` reports a false-positive failure ("ATTENTION! OpenCL
  kernel self-test failed."), even though cracking with
  `--self-test-disable` works correctly and the equivalent CUDA kernel
  passes its own self-test. Use `--self-test-disable` if you hit this
  on an affected PoCL build.
