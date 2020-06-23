module SEAL

using SEAL_jll

include("utilities.jl")
export check_return_value

include("version.jl")
export version_major, version_minor, version_patch, version

include("encryptionparams.jl")
export EncryptionParameters, SchemeType, get_poly_modulus_degree,
       set_poly_modulus_degree!, set_coeff_modulus!, coeff_modulus

include("modulus.jl")
export Modulus, SecLevelType, bit_count, value, coeff_modulus_create

include("context.jl")
export SEALContext, first_parms_id

include("publickey.jl")
export PublicKey

include("secretkey.jl")
export SecretKey

include("relinkeys.jl")
export RelinKeys

include("keygenerator.jl")
export KeyGenerator, public_key, secret_key, relin_keys_local, relin_keys

include("plaintext.jl")
export Plaintext

include("ciphertext.jl")
export Ciphertext, scale

include("encryptor.jl")
export Encryptor, encrypt!

include("evaluator.jl")
export Evaluator, square!, relinearize!, relinearize_inplace!, rescale_to_next!,
       rescale_to_next_inplace!, multiply_plain!, multiply_plain_inplace!

include("decryptor.jl")
export Decryptor

include("ckks.jl")
export CKKSEncoder, slot_count, encode!

include("memorymanager.jl")
export MemoryPoolHandle, memory_manager_get_pool


end
