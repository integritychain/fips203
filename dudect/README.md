An example constant-time workbench. It can be sensitive to config/defaults, so is
not entirely definitive. A work in progress.

See <https://docs.rs/dudect-bencher/latest/dudect_bencher/>

~~~
$ cd dudect  # this directory
$ RUSTFLAGS="-C target-cpu=native" cargo run --release -- --continuous full_flow

running 1 benchmark continuously
bench full_flow seeded with 0xfe84d163d7c04e60
bench full_flow ... : n == +0.199M, max t = -1.44267, max tau = -0.00323, (5/tau)^2 = 2396165
bench full_flow ... : n == +0.329M, max t = -1.36960, max tau = -0.00239, (5/tau)^2 = 4390143
bench full_flow ... : n == +0.045M, max t = +1.34098, max tau = +0.00631, (5/tau)^2 = 628087
bench full_flow ... : n == +0.059M, max t = +1.42716, max tau = +0.00587, (5/tau)^2 = 725853
bench full_flow ... : n == +0.073M, max t = +1.32158, max tau = +0.00488, (5/tau)^2 = 1051265
bench full_flow ... : n == +0.094M, max t = +1.27343, max tau = +0.00416, (5/tau)^2 = 1447412
bench full_flow ... : n == +0.102M, max t = +1.37215, max tau = +0.00430, (5/tau)^2 = 1349570
bench full_flow ... : n == +1.558M, max t = -1.84884, max tau = -0.00148, (5/tau)^2 = 11395685
bench full_flow ... : n == +1.744M, max t = -2.01548, max tau = -0.00153, (5/tau)^2 = 10731802
...
~~~
