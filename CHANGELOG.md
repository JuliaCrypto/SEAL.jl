# Changelog

This file only tracks changes at a very high, summarized level, omitting patch releases.

## SEAL dev
* ...

## SEAL v0.3.0
* Add `examples/6_serialization.jl` and `examples/7_performance.jl` and all corresponding
  functionality in the library itself
* Add `examples/examples.jl` with `seal_examples()` that allows to run the examples interactively
* New methods: `using_keyswitching`, `save_size`, `save!`, `load!`, `reserve!`, `encrypt_symmetric`,
  `encrypt_symmetric!`, `alloc_bytezcount`, `rotate_rows!`, `rotate_rows_inplace!`,
  `rotate_columns!`, `rotate_columns_inplace!`, `complex_conjugate!`, `complex_conjugate_inplace!`

## SEAL v0.2.0
* Full support for all functionality found in all SEAL examples.

## SEAL v0.1.0
* Initial release
* Support for most functionality found in `examples/1_bfv_basics.cpp`, `examples/4_ckks_basics.cpp`,
  `examples/5_rotation.cpp`
