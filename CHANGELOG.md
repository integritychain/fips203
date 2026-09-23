# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased so far...

- Prepare 0.5.0. The public API is unchanged and rand_core stays on 0.6; the version bump is the Rust 1.85 MSRV break.
- Enable the CCTV modulus and strcmp tests. Intermediate and unlucky vectors stay ignored because their encapsulation keys do not match final FIPS 203.
- Update NIST ACVP ML-KEM vectors, including the July 2026 encap/decap corrections. Decapsulation reads each `dk` from its test case, and key-check groups compare `try_from_bytes` with `testPassed`.
- NIST keygen tests for ML-KEM-768 and ML-KEM-1024 now use keygen_from_seed.
- Document bare-metal RNG use, and point the security advisory link at this repository.
- WASM demo: refresh the browser npm toolchain and rewrite the WASM README.
- WASM demo: point the fips203 path dependency at the parent directory and bump wasm-bindgen.
- Clear Clippy pedantic findings reported by current stable.
- ct_cm4: pin fixed to 1.30.0 so the Microbit sample still resolves on Rust 1.85.
- Bump Criterion to 0.5, which drops unmaintained atty, and pin textwrap to 0.16.2 so the dev-dependency tree stays buildable on Rust 1.85.
- CI: install the Clippy component on stable before running cargo clippy.
- CI: bump cargo-deny-action to v2 and move deny.toml graph and output settings into the v2 tables.
- Minor improvements to OSS FUZZ coverage; https://oss-fuzz.com/fuzzer-stats
- Updated (false positive) Golang vuln in dependency for test vectors
- Raise the minimum supported Rust version to 1.85 (Debian stable / trixie) in the crate manifests and CI.

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
