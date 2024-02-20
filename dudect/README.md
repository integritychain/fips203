An example constant-time workbench, not particularly definitive.

See <https://docs.rs/dudect-bencher/latest/dudect_bencher/>

~~~
$ cd dudect  # this directory


$ cargo run --release -- --continuous encaps
running 1 benchmark continuously
bench encaps seeded with 0x27391b59854589bd
bench encaps ... : n == +0.000M, max t = +1.81314, max tau = +0.17528, (5/tau)^2 = 813
bench encaps ... : n == +0.000M, max t = +1.86948, max tau = +0.09430, (5/tau)^2 = 2811
bench encaps ... : n == +0.001M, max t = +1.94892, max tau = +0.08010, (5/tau)^2 = 3896
bench encaps ... : n == +0.001M, max t = +2.76896, max tau = +0.09852, (5/tau)^2 = 2575
bench encaps ... : n == +0.001M, max t = +3.13701, max tau = +0.10895, (5/tau)^2 = 2106
bench encaps ... : n == +0.001M, max t = +2.91492, max tau = +0.09255, (5/tau)^2 = 2918
bench encaps ... : n == +0.001M, max t = +3.21354, max tau = +0.08635, (5/tau)^2 = 3352
bench encaps ... : n == +0.002M, max t = +3.24153, max tau = +0.08158, (5/tau)^2 = 3756
bench encaps ... : n == +0.002M, max t = +3.36906, max tau = +0.07992, (5/tau)^2 = 3913
...


$ cargo run --release -- --continuous decaps
running 1 benchmark continuously
bench decaps seeded with 0xec16eb4047bd7590
bench decaps ... : n == +0.000M, max t = -1.12523, max tau = -0.11252, (5/tau)^2 = 1974
bench decaps ... : n == +0.000M, max t = -1.68228, max tau = -0.16994, (5/tau)^2 = 865
bench decaps ... : n == +0.001M, max t = +1.55089, max tau = +0.06353, (5/tau)^2 = 6194
bench decaps ... : n == +0.001M, max t = +2.16336, max tau = +0.07668, (5/tau)^2 = 4252
bench decaps ... : n == +0.001M, max t = +2.23635, max tau = +0.07090, (5/tau)^2 = 4973
bench decaps ... : n == +0.001M, max t = +3.04987, max tau = +0.08826, (5/tau)^2 = 3209
bench decaps ... : n == +0.001M, max t = +3.73292, max tau = +0.09998, (5/tau)^2 = 2500
bench decaps ... : n == +0.002M, max t = +3.84010, max tau = +0.09618, (5/tau)^2 = 2702
bench decaps ... : n == +0.002M, max t = +3.64249, max tau = +0.08602, (5/tau)^2 = 3378
...
~~~
