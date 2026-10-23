# C Shared Object for ML-KEM

This crate provides a shared object (dynamically-linked library) using standard C FFI ABI that provides a functional implementation of ML-KEM.

The goals of this implementation are:

- simplicity
- correctness
- caller deals only with serialized objects
- no library-specific memory management (caller manages all objects)
- no internal state held by the library between calls
- minimal symbol visibility
- stable API/ABI

security-related goals:

- constant-time operations
- clean library RAM, best effort (the library wipes the secret buffers it uses before returning, but copies made when a key is moved or passed by value can remain on the stack)

non-goals are:

- speed
- efficiency
- size

# Paths considered but discarded

- Autogenerate stable C headers (e.g. with cbindgen); manually-crafted headers are probably fine, given the simplicity of the API/ABI


# Quick start

~~~
$ cd ffi   # this directory
$ cargo build
$ (cd tests && make)
$ cd python
$ FIPS203_PYTHON_TESTING_LIBRARY=../../target/debug/libfips203.so python3
>>> from fips203 import ML_KEM_512
>>> 
>>> (encapsulation_key, decapsulation_key) = ML_KEM_512.keygen()
>>> (ciphertext, shared_secret_1) = encapsulation_key.encaps()
>>> shared_secret_2 = decapsulation_key.decaps(ciphertext)
>>> assert(shared_secret_1 == shared_secret_2)
~~~

On macOS the library is `libfips203.dylib`.


# Header

Ship / include [`fips203.h`](fips203.h) with your application. It is hand-maintained (not
cbindgen). It includes `<stdint.h>` for portable integer types.

Compile C callers with something like `-I/path/to/ffi` (the directory that contains
`fips203.h`).


# Shared library names (Linux ELF SONAME)

`cargo build -p fips203-ffi` produces a cdylib named **`libfips203.so`** (or
`libfips203.dylib` on macOS) under `target/debug` or `target/release`.

On Linux (and other ELF targets), [`build.rs`](build.rs) also sets the ELF **SONAME** to
**`libfips203.so.0`** (major version from the crate). That means:

| Artifact | Role |
|---|---|
| `libfips203.so` | Link name Cargo emits; use `-lfips203` at link time |
| `libfips203.so.0` | Runtime name the dynamic loader looks up (SONAME) |

After install, distributors typically provide both: the versioned file (or symlink) that
matches the SONAME, plus an unversioned `libfips203.so` symlink for the linker.

For **in-tree** tests, `tests/Makefile` creates a local `libfips203.so.0` → `libfips203.so`
symlink next to Cargo’s output so `LD_LIBRARY_PATH` runs succeed without a full install.
If you link your own binary against a raw `target/*/libfips203.so` on Linux, either:

- create the same `libfips203.so.0` symlink beside it, or
- install the library with a packaging layout that provides the SONAME, or
- set an appropriate rpath / use `LD_LIBRARY_PATH` **and** ensure `libfips203.so.0`
  resolves (a bare `libfips203.so` alone is not enough when SONAME is `.so.0`).

On **macOS** and iOS, `build.rs` sets the install name to `@rpath/libfips203.dylib` instead of
an ELF-style SONAME; the Makefile does not need a `.so.0` symlink there. On **Android** the
SONAME is unversioned, `libfips203.so`, because an APK holds only `lib*.so` files. Windows and
WebAssembly builds get no extra linker flags. `build.rs` picks these by the target, not the
build machine, so cross builds get the right ones.


# Linking a C program (local build)

Example against a debug build from the repo root:

~~~
$ cargo build -p fips203-ffi
$ cc -o myapp myapp.c \
    -Iffi \
    -L target/debug -Wl,-rpath,$PWD/target/debug \
    -lfips203
# Linux: ensure runtime SONAME resolves, e.g.:
$ ln -sfn libfips203.so target/debug/libfips203.so.0
$ ./myapp
~~~


# pkg-config

`build.rs` writes a minimal `fips203.pc` into Cargo’s `OUT_DIR` (not into `target/debug`
by itself). It currently only declares `Libs: -lfips203` (no `Cflags` include path).
Treat it as a starting point for packagers; you will still need to install `fips203.h`
and set `-I` / `Cflags` appropriately for your layout.
