# Fuzzing (SPEC §11.4)

One target, `cbor_decode`: the dc-cbor decoder on arbitrary bytes. Its properties are listed in `fuzz_targets/cbor_decode.rs`.

With cargo-fuzz and a current nightly:

```sh
cargo +nightly fuzz run cbor_decode fuzz/corpus-work fuzz/corpus/cbor_decode
```

Without cargo-fuzz, on the pinned stable toolchain, the same coverage instrumentation that cargo-fuzz passes (all of it stable `-C` options), without AddressSanitizer (`-Zsanitizer` is nightly-only; the decoder has no `unsafe`):

```sh
cd fuzz
RUSTFLAGS="--cfg fuzzing -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table \
  -Cllvm-args=-sanitizer-coverage-trace-compares" \
  mkdir -p corpus-work artifacts
  cargo run --release --bin cbor_decode -- corpus-work corpus/cbor_decode \
  -artifact_prefix=artifacts/ -max_total_time=600
```

`corpus/cbor_decode/` holds the committed seeds (the canonical structures in `tests/vectors/`). libFuzzer writes new inputs to the first directory, `corpus-work/`, which is not committed; crashes go to `artifacts/`.
