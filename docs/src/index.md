# SEAL.jl

**SEAL.jl** is a Julia package that wraps the
[SEAL](https://github.com/microsoft/SEAL) library for homomorphic encryption. It
supports the Brakerski/Fan-Vercauteren (BFV) and Cheon-Kim-Kim-Song (CKKS, also
known as HEAAN in literature) schemes and exposes the homomorphic encryption
capabilitites of SEAL in a (mostly) intuitive and Julian way. SEAL.jl is
published under the same permissive MIT license as the original SEAL library.


## Implementation strategy

SEAL.jl is *work-in-progress*, thus only a subset of the many capabilities of
the SEAL library are so far supported ([PRs are welcome!](@ref Contributing)). In
general, SEAL.jl makes use of the C bindings provided by SEAL, but tries to
mimic SEAL's *C++* API as close as possible. That is, file names,
function/variable names, the order of arguments etc. are as close as
possible to the SEAL C++ code as possible. The reason for this is that the SEAL
library provides excellent inline code documentation, thus by reading (and
understanding) the comments in the C++ files you should immediately be able to
reproduce the same implementation with SEAL.jl.

However, since C++ and Julia are quite different, some implementation details do
not directly translate from one language to the other. Also, the Julia community
has a few very strong conventions that would make it difficult for an
experienced Julia user if they were violated. Thus, when trying to recreate C++
SEAL example with SEAL.jl, there are a few things to watch out for:

* Functions that modify their input are suffixed by `!`.
* Function arguments that are modified come first (but the rest remains in
  order) .
* When translating C++ member function to Julia, the "owning" object is always
  passed as the last argument.
* While `x.size()` in C++ returns a scalar, length-like value, `size(x)` in
  Julia is expected to return a tuple, which is also the case in SEAL.jl.

The next example shows the first three items in practice. The C++ code
snippet
```c++
evaluator.multiply_plain(x1_encrypted, plain_coeff3, x1_encrypted_coeff3);
```
is translated to the following Julia code:
```julia
multiply_plain!(x1_encrypted_coeff3, x1_encrypted, plain_coeff3, evaluator)
```
Note the trailing `!`, the fact that `x1_encrypted_coeff3` as the modified input
variable is now the first argument, and `evaluator` being passed as the last
argument.


## Authors
SEAL.jl was initiated by
[Michael Schlottke-Lakemper](https://www.mi.uni-koeln.de/NumSim/schlottke-lakemper)
(University of Cologne, Germany), who is also the principal developer of
SEAL.jl.


## License and contributing
SEAL.jl is licensed under the MIT license (see [License](@ref)). Since SEAL.jl is
an open-source project, we are very happy to accept contributions from the
community. Please refer to [Contributing](@ref) for more details.


## Acknowledgements
This Julia package would have not been possible without the excellent work of
the developers of the [SEAL](https://github.com/microsoft/SEAL) library. Their
high-quality code documentation plus the fact that they provide C bindings for
the entire functionality of the SEAL C++ library have made developing SEAL.jl
a breeze.
