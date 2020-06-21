module SEAL

const seal_library_path = "/home/mschlott/.pool/seal/3.5.4/lib/libsealc.so"

export version_major, version_minor, version_patch, version
export EncryptionParameters, SchemeType, get_poly_modulus_degree,
       set_poly_modulus_degree!, set_coeff_modulus!, coeff_modulus
export Modulus, SecLevelType, bit_count, value, coeff_modulus_create
export SEALContext
export PublicKey
export SecretKey
export RelinKeys
export KeyGenerator, public_key, secret_key, relin_keys_local, relin_keys
export Encryptor

include("version.jl")
include("encryptionparams.jl")
include("modulus.jl")
include("context.jl")
include("publickey.jl")
include("secretkey.jl")
include("relinkeys.jl")
include("keygenerator.jl")
include("encryptor.jl")

end
