This is a work in progress, but good results currently.

Harness code is in fuzz/fuzz_targets/fuzz_all.rs. The Cargo.toml file specifies
that overflow-checks and debug-assertions are enabled (so the fuzzer can find
these panics).

See: https://rust-fuzz.github.io/book/cargo-fuzz.html

~~~
$ cd fuzz  # this directory; you may need to install cargo fuzz
$ rustup default nightly
$ mkdir -p corpus/fuzz_all
$ dd if=/dev/zero bs=1 count=3328 > corpus/fuzz_all/seed0
$ for i in $(seq 1 2); do head -c 3328 </dev/urandom > corpus/fuzz_all/seed$i; done
$ dd if=/dev/zero bs=1 count=3328 | tr '\0x00' '\377' > corpus/fuzz_all/seed3
$ cargo fuzz run fuzz_all -j 4
~~~

Coverage status of ml_kem_512 is robust, see:

~~~
#30756: cov: 7503 ft: 5982 corp: 73 exec/s 9 oom/timeout/crash: 0/0/0 time: 960s job: 84 dft_time: 0

# Warning: the following tools are tricky to install/configure
$ cargo install cargo-cov
$ rustup component add llvm-tools-preview
$ cargo fuzz coverage fuzz_all
$ cargo cov -- show target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/fuzz_all \
       --format=html -instr-profile=coverage/fuzz_all/coverage.profdata > index.html
~~~
