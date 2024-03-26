An example constant-time workbench. It can be sensitive to config/defaults, so
not entirely definitive. A work in progress.

See <https://docs.rs/dudect-bencher/latest/dudect_bencher/>

~~~
$ cd dudect  # this directory
$ RUSTFLAGS="-C target-cpu=native" cargo run --release -- --continuous full_flow

(on a questionable laptop vm)

running 1 benchmark continuously
bench full_flow seeded with 0x02d88362e06d1fc0
bench full_flow ... : n == +0.013M, max t = -2.03798, max tau = -0.01761, (5/tau)^2 = 80603
bench full_flow ... : n == +0.225M, max t = +2.04956, max tau = +0.00432, (5/tau)^2 = 1336552
bench full_flow ... : n == +0.382M, max t = +2.68578, max tau = +0.00434, (5/tau)^2 = 1325294
...
~~~
