~~~
Fuzzing
https://rust-fuzz.github.io/book/cargo-fuzz.html
  cd fuzz
  rustup default nightly
  head -c 3200 </dev/urandom > corpus/seed1
  cargo fuzz run fuzz_all -j 4
~~~
