# SEAL.jl

[![Documentation-stable](https://img.shields.io/badge/docs-stable-blue.svg)](https://juliacrypto.github.io/SEAL.jl/stable)
[![Documentation-dev](https://img.shields.io/badge/docs-dev-blue.svg)](https://juliacrypto.github.io/SEAL.jl/dev)
[![Build Status](https://github.com/JuliaCrypto/SEAL.jl/workflows/CI/badge.svg)](https://github.com/JuliaCrypto/SEAL.jl/actions?query=workflow%3ACI)
[![codecov](https://codecov.io/gh/JuliaCrypto/SEAL.jl/branch/main/graph/badge.svg)](https://codecov.io/gh/JuliaCrypto/SEAL.jl)
[![License: MIT](https://img.shields.io/badge/License-MIT-success.svg)](https://opensource.org/licenses/MIT)

**SEAL.jl** is a Julia package that wraps the Microsoft
[SEAL](https://github.com/microsoft/SEAL) library for homomorphic encryption. It
supports the Brakerski/Fan-Vercauteren (BFV) and Cheon-Kim-Kim-Song (CKKS, also
known as HEAAN in literature) schemes and exposes the homomorphic encryption
capabilitites of SEAL in a (mostly) intuitive and Julian way. SEAL.jl is
published under the same permissive MIT license as the Microsoft SEAL library.

Currently, SEAL.jl supports all operations that are used in the examples of the
[SEAL library](https://github.com/microsoft/SEAL/tree/master/native/examples).
This includes encoding and encryption, addition and multiplication, rotation,
relinearization and modulus switching for the BFV and CKKS schemes.


## Installation
To install SEAL.jl, start a Julia REPL, hit `]` to enter Julia's `Pkg` mode, and
then execute
```julia
(@v1.5) pkg> add SEAL
```
Alternatively, you can install SEAL.jl by using `Pkg` directly, i.e., by running
```shell
julia -e 'using Pkg; Pkg.add("SEAL")'
```
SEAL.jl depends on the binary distribution of the SEAL library, which is
available as a Julia package `SEAL_jll.jl` and which is automatically installed
as a dependency.

*Note: Currently SEAL_jll.jl is not available on Windows, thus SEAL.jl will
work only on Linux, MacOS and FreeBSD. Also, SEAL_jll.jl does not work on 32-bit
systems.*


## Getting started
### Usage
After installation, load SEAL.jl by running
```julia
using SEAL
```
in the REPL. A **minimal** working example for encrypting an array of integers using the BFV
scheme, squaring it, and decrypting it, looks as follows:
```julia
julia> using SEAL
[ Info: Precompiling SEAL [bac81e26-86e4-4b48-8696-7d0406d5dbc1]

julia> parms = EncryptionParameters(SchemeType.bfv)
EncryptionParameters(Ptr{Nothing} @0x0000000002e1d3a0)

julia> poly_modulus_degree = 4096
4096

julia> set_poly_modulus_degree!(parms, poly_modulus_degree)
EncryptionParameters(Ptr{Nothing} @0x0000000002e1d3a0)

julia> set_coeff_modulus!(parms, coeff_modulus_bfv_default(poly_modulus_degree))
EncryptionParameters(Ptr{Nothing} @0x0000000002e1d3a0)

julia> set_plain_modulus!(parms, plain_modulus_batching(poly_modulus_degree, 20))
EncryptionParameters(Ptr{Nothing} @0x0000000002e1d3a0)

julia> context = SEALContext(parms)
SEALContext(Ptr{Nothing} @0x0000000004298440)

julia> keygen = KeyGenerator(context)
KeyGenerator(Ptr{Nothing} @0x00000000021ef540)

julia> public_key_ = PublicKey()
PublicKey(Ptr{Nothing} @0x0000000002272610)

julia> create_public_key!(public_key_, keygen)

julia> secret_key_ = secret_key(keygen)
SecretKey(Ptr{Nothing} @0x0000000001cec2a0)

julia> encryptor = Encryptor(context, public_key_)
Encryptor(Ptr{Nothing} @0x0000000001cd4480)

julia> evaluator = Evaluator(context)
Evaluator(Ptr{Nothing} @0x000000000428bdd0)

julia> decryptor = Decryptor(context, secret_key_)
Decryptor(Ptr{Nothing} @0x00000000037670d0)

julia> batch_encoder = BatchEncoder(context)
BatchEncoder(Ptr{Nothing} @0x0000000001fb4bd0, SEALContext(Ptr{Nothing} @0x0000000001b87780))

julia> pod_matrix = collect(UInt64, 1:slot_count(batch_encoder));

julia> Int.(vcat(pod_matrix[1:3], pod_matrix[end-3:end]))
7-element Array{Int64,1}:
    1
    2
    3
 4093
 4094
 4095
 4096

julia> plain_matrix = Plaintext()
Plaintext(Ptr{Nothing} @0x00000000042db6e0)

julia> encode!(plain_matrix, pod_matrix, batch_encoder)
Plaintext(Ptr{Nothing} @0x0000000002ce0370)

julia> encrypted_matrix = Ciphertext()
Ciphertext(Ptr{Nothing} @0x0000000002d91b80)

julia> encrypt!(encrypted_matrix, plain_matrix, encryptor)
Ciphertext(Ptr{Nothing} @0x0000000002d91b80)

julia> add_inplace!(encrypted_matrix, encrypted_matrix, evaluator)
Ciphertext(Ptr{Nothing} @0x0000000002ce1280)

julia> plain_result = Plaintext()
Plaintext(Ptr{Nothing} @0x0000000004591550)

julia> decrypt!(plain_result, encrypted_matrix, decryptor)
Plaintext(Ptr{Nothing} @0x0000000004591550)

julia> decode!(pod_matrix, plain_result, batch_encoder);

julia> Int.(vcat(pod_matrix[1:3], pod_matrix[end-3:end]))
7-element Array{Int64,1}:
    2
    4
    6
 8186
 8188
 8190
 8192
```

### Examples
As you can see, using homomorphic encryption is quite involved: You need to pick
a scheme, provide sensible encryption parameters, encode your raw data into
plaintext, encrypt it to ciphertext, perform your arithmetic operations on it,
and then decrypt and decode again.  Therefore, before starting to use SEAL.jl
for your own applications, it is **highly recommended** to have a look at the
examples in the
[`examples/`](examples/)
directory. Otherwise it will be very likely that you are using SEAL.jl (and SEAL) in a
way that is either not secure, will produce unexpected results, or just crashes.
The examples included in SEAL.jl follow almost line-by-line the examples provided by the
[SEAL library](https://github.com/microsoft/SEAL/tree/master/native/examples).
For example, the snippet above is based on the `example_batch_encoder()` function in
[`examples/2_encoders.jl`](examples/2_encoders.jl).
The full list of examples is as follows:

|SEAL.jl             |SEAL (C++)           |Description                                                                 |
|--------------------|---------------------|----------------------------------------------------------------------------|
|`examples.jl`       |`examples.cpp`       |The example runner application                                              |
|`1_bfv_basics.jl`   |`1_bfv_basics.cpp`   |Encrypted modular arithmetic using the BFV scheme                           |
|`2_encoders.jl`     |`2_encoders.cpp`     |Encoding more complex data into Microsoft SEAL plaintext objects            |
|`3_levels.jl`       |`3_levels.cpp`       |Introduces the concept of levels; prerequisite for using the CKKS scheme    |
|`4_ckks_basics.jl`  |`4_ckks_basics.cpp`  |Encrypted real number arithmetic using the CKKS scheme                      |
|`5_rotation.jl`     |`5_rotation.cpp`     |Performing cyclic rotations on encrypted vectors in the BFV and CKKS schemes|
|`6_serialization.jl`|`6_serialization.cpp`|Serializing objects in Microsoft SEAL                                       |
|`7_performance.jl`  |`7_performance.cpp`  |Performance tests                                                           |

To run the examples, first install SEAL.jl (as shown [above](#usage)) and clone this repository:
```shell
git clone https://github.com/JuliaCrypto/SEAL.jl.git
```
Then, run Julia and include `examples/examples.jl` before executing `seal_examples()`:
```shell
julia --project=. -e 'include("SEAL.jl/examples/examples.jl"); seal_examples()'
```

You will be shown an interactive prompt that lets you run any of the available
examples:
```
Microsoft SEAL version: 3.6.2
+---------------------------------------------------------+
| The following examples should be executed while reading |
| comments in associated files in examples/.              |
+---------------------------------------------------------+
| Examples                   | Source Files               |
+----------------------------+----------------------------+
| 1. BFV Basics              | 1_bfv_basics.jl            |
| 2. Encoders                | 2_encoders.jl              |
| 3. Levels                  | 3_levels.jl                |
| 4. CKKS Basics             | 4_ckks_basics.jl           |
| 5. Rotation                | 5_rotation.jl              |
| 6. Serialization           | 6_serialization.jl         |
| 7. Performance Test        | 7_performance.jl           |
+----------------------------+----------------------------+
[      0 MB] Total allocation from the memory pool

> Run example (1 ~ 7) or exit (0): 
```
Since the examples will not create or modify any files, feel free to run them from
any directory.


## Implementation strategy

SEAL.jl is *work-in-progress*, thus only a subset of the many capabilities of
the SEAL library are so far supported ([PRs are welcome!](CONTRIBUTING.md)). In
general, SEAL.jl makes use of the C bindings provided by SEAL, but tries to
mimic SEAL's *C++* API as close as possible. That is, file names,
function/variable names, the order of arguments etc. are as close as
possible to the SEAL C++ code as possible. The reason for this is that the SEAL
library provides excellent inline code documentation, thus by reading (and
understanding) the comments in the C++ files you should immediately be able to
reproduce the same implementation with SEAL.jl.

However, some implementation details do not translate well from C++ to
Julia. Also, the Julia community has a few strong conventions that if violated
would make it unnecessarily difficult for experienced Julia users to use SEAL.jl
correctly. Thus, when trying to recreate SEAL examples written in C++ with
SEAL.jl in Julia, there are a few things to watch out for:

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
SEAL.jl is licensed under the MIT license (see [LICENSE.md](LICENSE.md)). Since SEAL.jl is
an open-source project, we are very happy to accept contributions from the
community. Please refer to [CONTRIBUTING.md](CONTRIBUTING.md) for more details.


## Acknowledgements
This Julia package would have not been possible without the excellent work of
the developers of the [SEAL](https://github.com/microsoft/SEAL) library. Their
high-quality code documentation plus the fact that they provide C bindings for
the entire functionality of the SEAL C++ library have made developing SEAL.jl
a breeze.
