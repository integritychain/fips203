This is a work in progress, but off to a strong start.

~~~
Fuzzing
https://rust-fuzz.github.io/book/cargo-fuzz.html
  cd fuzz
  rustup default nightly
  head -c 3328 </dev/urandom > corpus/fuzz_all/seed1
  cargo fuzz run fuzz_all -j 4
~~~

Coverage visualization is in-flight. Currently:

~~~
#246109: cov: 3364 ft: 2218 corp: 99 exec/s 669 oom/timeout/crash: 0/0/0 time: 105s job: 26 dft_time: 0
~~~
