An example constant-time workbench. It can be sensitive to config/defaults, so is
not entirely definitive. A work in progress.

See <https://docs.rs/dudect-bencher/latest/dudect_bencher/>

> t-values greater than 5 are generally considered a good indication that the function is not constant time. t-values less than 5 does not necessarily imply that the function is constant-time, since there may be other input distributions under which the function behaves significantly differently.

~~~
October 13, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8 Circa 2017 w/ Rust 1.81

$ cd dudect  # this directory
$ cargo clean
$ time RUSTFLAGS="-C target-cpu=native" cargo run --release

...
   Compiling fips203 v0.4.1 (/home/eric/work/fips203)
   Compiling fips203-dudect v0.4.1 (/home/eric/work/fips203/dudect)
    Finished `release` profile [optimized + debuginfo] target(s) in 19.22s
     Running `target/release/fips203-dudect`

running 1 bench
bench full_flow seeded with 0x247c7db23373903d
bench full_flow ... : n == +8.342M, max t = -1.36340, max tau = -0.00047, (5/tau)^2 = 112196681

dudect benches complete


real	66m16.357s
user	66m29.427s
~~~
