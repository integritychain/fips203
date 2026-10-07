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
- `DecapsKey::try_from_bytes` rejects a key whose secret vector has a coefficient of q or more. Such a key used to deserialize, then fail in `try_decaps`.
- Secret intermediate values are wiped before each operation returns (FIPS 203 §3.3). This needs `sha3` 0.10.9 or later.
- The Python module (`ffi/python`) loads `libfips203` from `FIPS203_PYTHON_TESTING_LIBRARY` when that is set, otherwise from the system library path. If neither finds it, import raises an `OSError` that names the library. It no longer falls back to `../../target/debug/libfips203.{so,dylib}`. That path is relative to the current directory, so it only worked from `ffi/python` in a source checkout, and from any other directory it loaded whatever library sat at that path. The `fips204` and `fips205` modules load the same way.

### Fixed
- `ml_kem_populate_seed` (FFI) returns `ML_KEM_KEYGEN_ERROR` if the OS random number generator fails. It used to abort the process.
- `ffi/fips203.h` declares its `ML_KEM_*` error codes `static const`. Before, two C files that included the header failed to link with duplicate symbols.
- The Python module reports `__version__` 0.5.0. It said 0.4.3, and `pyproject.toml` takes the package version from it.
- The Python README and module docstring examples run as written. The serialization example imports `Seed`. The deserialization example opens its file `'rb'` (not `'b'`) and calls `encaps()` (not `Encaps()`). The docstring copy had a missing parenthesis. The specification link points at final FIPS 203, not the draft.

## 0.4.3 (2025-02-25)

- Synchronizing with fips203-ffi fix release; adjust cargo outdated issue
- Added project into OS-Fuzz https://github.com/google/oss-fuzz
- Added fuzzing corpus along with README.md edits and code doc/comments improvements

## 0.4.2 (2024-12-23)

- Added `encaps_from_seed`
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

## 0.1.1 (2024-01-07)

- Fully functional in all three parameter sets

## 0.1.0 (2023-10-15)

- Initial API release skeleton
