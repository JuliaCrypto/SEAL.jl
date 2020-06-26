module SEAL

# SEAL_jll provides `libsealc`, which we will use in this package
using SEAL_jll

"""
    SEALObject

Abstract parent type for all types based on SEAL classes.
"""
abstract type SEALObject end

"""
    handle(x::SEALObject)

Return the raw C pointer to where `x` resides in memory.
"""
handle(x::SEALObject) = x.handle

export SEALObject, handle

Base.unsafe_convert(::Type{Ptr{Cvoid}}, x::SEALObject) = handle(x)

include("auxiliary.jl")
# Julia-only auxiliary methods -> no exports

include("version.jl")
export version_major, version_minor, version_patch, version

include("encryptionparams.jl")
export EncryptionParameters, SchemeType, get_poly_modulus_degree,
       set_poly_modulus_degree!, set_coeff_modulus!, coeff_modulus,
       scheme, plain_modulus, set_plain_modulus!

include("modulus.jl")
export Modulus, SecLevelType, bit_count, value, coeff_modulus_create, coeff_modulus_bfv_default

include("context.jl")
export SEALContext, first_parms_id, get_context_data, key_context_data, parameter_error_message
export ContextData, chain_index, parms, total_coeff_modulus_bit_count

include("publickey.jl")
export PublicKey

include("secretkey.jl")
export SecretKey

include("galoiskeys.jl")
export GaloisKeys

include("relinkeys.jl")
export RelinKeys

include("keygenerator.jl")
export KeyGenerator, public_key, secret_key, relin_keys_local, relin_keys, galois_keys_local

include("plaintext.jl")
export Plaintext, scale, scale!, parms_id, to_string

include("ciphertext.jl")
export Ciphertext, scale, scale!, parms_id, size, length

include("encryptor.jl")
export Encryptor, encrypt!

include("evaluator.jl")
export Evaluator, square!, square_inplace!, relinearize!, relinearize_inplace!, rescale_to_next!,
       rescale_to_next_inplace!, multiply_plain!, multiply_plain_inplace!, multiply!,
       multiply_inplace!, mod_switch_to!, mod_switch_to_inplace!, add!, add_inplace!,
       add_plain!, add_plain_inplace!, rotate_vector!, rotate_vector_inplace!, negate!

include("decryptor.jl")
export Decryptor, decrypt!, invariant_noise_budget

include("ckks.jl")
export CKKSEncoder, slot_count, encode!, decode!

include("intencoder.jl")
export IntegerEncoder, encode!, encode, decode_int32, plain_modulus

include("memorymanager.jl")
export MemoryPoolHandle, memory_manager_get_pool


end
