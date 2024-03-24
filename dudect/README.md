An example constant-time workbench. It is not particularly definitive as it is
rather sensitive to configuration & defaults.

See <https://docs.rs/dudect-bencher/latest/dudect_bencher/>

~~~
$ cd dudect  # this directory
$ RUSTFLAGS="-C target-cpu=native" cargo run --release -- --continuous full_flow


~~~
