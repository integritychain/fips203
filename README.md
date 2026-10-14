# [IntegrityChain]: FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/fips203.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:fips203)

[FIPS 203] Module-Lattice-Based Key-Encapsulation Mechanism Standard written in pure Rust for server, desktop, browser
and embedded applications. The source repository includes examples demonstrating benchmarking, code provenance, an
embedded target, constant-time statistical measurements, a fuzzing harness, WASM execution, a C FFI shared library and
Python bindings.

This crate implements the released FIPS 203 standard in pure Rust with minimal and mainstream dependencies, and without
any unsafe code. All three security parameter sets are fully functional and tested. Key generation, encapsulation and
decapsulation are constant-time: they do not branch on secret data, apart from expanding the matrix from the public
seed ρ. The crate does not require the standard library (it is `#![no_std]`), makes no heap allocations (no `alloc`
needed), and exposes the `RNG`, so it suits the full range of applications from server down to bare metal. The API is
stabilized, and the code is heavily biased towards safety and correctness.

See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf> for a full description of the target functionality.

The functionality is extremely simple to use, as demonstrated by the following example.

~~~rust
# #[cfg(all(feature = "ml-kem-512", feature = "default-rng"))] {
// Use the desired target parameter set.
use fips203::ml_kem_512; // Could also be ml_kem_768 or ml_kem_1024.
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

// Alice runs `try_keygen()` and then serializes the encaps key `ek` for Bob (to bytes).
let (alice_ek, alice_dk) = ml_kem_512::KG::try_keygen().unwrap();
let alice_ek_bytes = alice_ek.into_bytes();

// Alice sends the encaps key `ek_bytes` to Bob.
let bob_ek_bytes = alice_ek_bytes;

// Bob deserializes the encaps `ek_bytes` and then runs `try_encaps()` to get the shared
// secret `ssk` and ciphertext `ct`. He serializes the ciphertext `ct` for Alice (to bytes).
let bob_ek = ml_kem_512::EncapsKey::try_from_bytes(bob_ek_bytes).unwrap();
let (bob_ssk_bytes, bob_ct) = bob_ek.try_encaps().unwrap();
let bob_ct_bytes = bob_ct.into_bytes();

// Bob sends the ciphertext `ct_bytes` to Alice
let alice_ct_bytes = bob_ct_bytes;

// Alice deserializes the ciphertext `ct` and runs `try_decaps()` with her decaps key
let alice_ct = ml_kem_512::CipherText::try_from_bytes(alice_ct_bytes).unwrap();
let alice_ssk_bytes = alice_dk.try_decaps(&alice_ct).unwrap();

// Alice and Bob will now have the same secret key
assert_eq!(bob_ssk_bytes, alice_ssk_bytes);
# }
~~~

The Rust [Documentation][docs-link] lives under each **Module** corresponding to the desired
[security parameter][docs-modules].

## Notes

* This crate is fully functional and corresponds to the final released FIPS 203 (August 13, 2024).
* Constant-time: key generation, encapsulation and decapsulation do not branch on secret data. The
  one exception is `SampleNTT`'s rejection sampling, which expands the matrix Â from the seed ρ;
  ρ is public, carried in the encapsulation key. Checked by source review, by cycle counts on the
  embedded target ([`ct_cm4/`](ct_cm4/)), and by the [`dudect`](dudect/README.md) measurements.
  The claim is at the source level: the compiler and CPU are trusted not to add secret-dependent
  timing, and the caller's RNG is outside it.
* FIPS 203 places specific requirements on randomness (section 3.3), hence the exposed `RNG`. RNG
  integration uses **`rand_core` 0.6**: custom generators implement `CryptoRngCore` (`CryptoRng` +
  `RngCore`), which this crate re-exports along with `RngError`. Key generation and encapsulation
  call `try_fill_bytes`, so handle its error or use the seed-based functions.
* The default features enable `default-rng` plus all three parameter sets. That OS RNG path is for
  hosted environments; it will **not** compile on bare-metal targets that lack a `getrandom`
  backend (for example `thumbv7em-none-eabi`). Embedded builds use `default-features = false`,
  the parameter-set feature they need, and the seed-based functions or `*_with_rng`, as in
  [`ct_cm4/`](ct_cm4/):
  `fips203 = { version = "0.5", default-features = false, features = ["ml-kem-512"] }`.
* Test vectors: the NIST ACVP keyGen and encapDecap vectors (including decapsulation keys given as
  seeds), the C2SP Wycheproof and CCTV ML-KEM vectors, and Go's accumulated ML-KEM-768 test run in
  the test suite, and the Python bindings apply the ACVP files through the C ABI. The vector files
  stay in the repository; the published crate omits them.
* A C shared library (`libfips203`, published as `fips203-ffi`) with Python bindings, and a WASM
  browser demo, are described in [`ffi/README.md`](ffi/README.md) and
  [`wasm/README.md`](wasm/README.md).
* Requires Rust **1.85** or higher (Debian stable, trixie). The minimum supported Rust version may
  change in the future, but only with a minor version bump (once the major version is above 0).
* All on-by-default features of this library are covered by `SemVer`.

## License

Contents are licensed under either the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](http://opensource.org/licenses/MIT) at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/fips203
[crate-link]: https://crates.io/crates/fips203
[docs-image]: https://docs.rs/fips203/badge.svg
[docs-link]: https://docs.rs/fips203/
[docs-modules]: https://docs.rs/fips203/latest/fips203/#modules
[build-image]: https://github.com/integritychain/fips203/workflows/test/badge.svg
[build-link]: https://github.com/integritychain/fips203/actions?query=workflow%3Atest
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg

[//]: # (general links)

[IntegrityChain]: https://github.com/integritychain/
[FIPS 203]: https://csrc.nist.gov/pubs/fips/203/final
