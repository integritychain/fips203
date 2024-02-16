~~~
Fuzzing
https://rust-fuzz.github.io/book/cargo-fuzz.html
  cd fuzz
  rustup default nightly
  head -c 3328 </dev/urandom > corpus/fuzz_all/seed1
  cargo fuzz run fuzz_all -j 4
~~~
