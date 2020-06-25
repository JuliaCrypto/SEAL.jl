# SEAL.jl

[![Documentation](https://img.shields.io/badge/docs-dev-blue.svg)](https://sloede.github.io/SEAL.jl/dev)
[![Build Status](https://travis-ci.com/sloede/SEAL.jl.svg?branch=master)](https://travis-ci.com/sloede/SEAL.jl)
[![codecov](https://codecov.io/gh/sloede/SEAL.jl/branch/master/graph/badge.svg?token=CCJ4EO3HW8)](https://codecov.io/gh/sloede/SEAL.jl)
[![Coverage Status](https://coveralls.io/repos/github/sloede/SEAL.jl/badge.svg)](https://coveralls.io/github/sloede/SEAL.jl)

*SEAL.jl* is a Julia package that wraps the Microsoft
[SEAL](https://github.com/microsoft/SEAL) library. It exposes the homomorphic
encryption capabilitites of SEAL in an intuitive and Julian way.

## Implementation strategy

* Use `libsealc`, the SEAL-provided C bindings
* Stick to SEAL's *C++* API as close as possible: file names, function names,
  order of arguments etc.
* Exceptions only to be consistent with Julia best practices:
  * Functions that modify their input are suffixed by `!`
  * Function arguments that are modified come first (but the rest remains in
    order)
  * `size(x)` will return a tuple `(length_of_x,)`

## Authors
SEAL.jl was initiated by
[Michael Schlottke-Lakemper](https://www.mi.uni-koeln.de/NumSim/schlottke-lakemper),
who is also the principal developer of SEAL.jl.

## License and contributing
SEAL.jl is licensed under the MIT license (see [LICENSE.md](LICENSE.md)). Since SEAL.jl is
an open-source project, we are very happy to accept contributions from the
community. Please refer to [CONTRIBUTING.md](CONTRIBUTING.md) for more details.
