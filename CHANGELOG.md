# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.0 (in progress)

### Migration from 0.4.x
- Public API is unchanged. Depend on `fips203 = "0.5"`. The bump is the MSRV break.
- MSRV is **1.85**.
- RNG stays `rand_core` 0.6. `CryptoRng`, `RngCore`, and `RngError` are re-exported.
- Default features enable the OS RNG and all three parameter sets. That does not build on bare metal. Use `default-features = false`, one `ml-kem-*` feature, and seeds or `*_with_rng`.

### Changed
- Checked against the current NIST ACVP ML-KEM vectors, including the July 2026 encap/decap corrections.
- Security reports go to this repository.

## 0.4.3 (2024-02-25)

- Synchronizing with fips203-ffi fix release; adjust cargo outdated issue
- Added project into OS-Fuzz https://github.com/google/oss-fuzz
- Added fuzzing corpus along with README.md edits and code doc/comments improvements

## 0.4.2 (2024-12-23)

- Added decaps with seed
- Another fuzzing harness (experimental wip)

## 0.4.1 (2024-10-13)

- Minor internal polish; alignment with ffi functionality
- Revisit/revise supporting benches, ct_cm4, dudect, ffi and wasm code

## 0.4.0 (2024-09-12)

- Updated to final release of FIPS 203 as of August 13, 2024; Passes NIST tests
- Added `keygen_from_seed(d, z)` API

## 0.2.1 (2024-05-01)

- Very minor dev dependency downgrade for compat (flate2)

## 0.2.0 (2024-04-26)

- Removed `_vt` suffix from top-level API as constant-time operation is now measured

## 0.1.6 (2024-04-24)

- Additional tests in `validate_keypair_vt()`, implemented second round review feedback

## 0.1.5 (2024-04-14)

- Significant performance optimizations and internal revisions based upon review feedback

## 0.1.4 (2024-04-01)

- Constant-time fixes and measurement
- Significant internal clean up, additional SerDes validation

## 0.1.3 (2024-02-27)

- Adjustments to dependency versions to support MSRV 1.70

## 0.1.2 (2024-02-21)

- Added (serialized) keypair validation functionality
- General clean-up, refined checks, some constant-time work
- Cargo deny and codecov; revised bench, fuzz, dudect and ct_cm4

## 0.1.1 (2023-10-30)

- Fully functional in all three parameter sets

## 0.1.0 (2023-10-15)

- Initial API release skeleton
