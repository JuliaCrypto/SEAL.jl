module SEAL

const seal_library_path = "/home/mschlott/.pool/seal/3.5.4/lib/libsealc.so"

export version_major, version_minor, version_patch, version
export EncryptionParameters, SchemeType, none, bfv, ckks, get_poly_modulus_degree,
       set_poly_modulus_degree!, set_coeff_modulus!, coeff_modulus
export Modulus, bit_count, value, coeff_modulus_create

include("version.jl")
include("encryptionparams.jl")
include("modulus.jl")

end
