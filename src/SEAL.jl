module SEAL

# SEAL_jll provides `libsealc`, which we will use in this package
using SEAL_jll

"""
    SEALObject

Abstract parent type for all types based on SEAL classes.
"""
abstract type SEALObject end

"""
    handle(object::SEALObject)

Return the raw C pointer to where `object` resides in memory.
"""
handle(object::SEALObject) = object.handle

export SEALObject, handle

Base.unsafe_convert(::Type{Ptr{Cvoid}}, object::SEALObject) = handle(object)

include("auxiliary.jl")
# Julia-only auxiliary methods -> no exports

include("version.jl")
export version_major, version_minor, version_patch, version

include("modulus.jl")
export Modulus, SecLevelType, bit_count, value, coeff_modulus_create, coeff_modulus_bfv_default

include("serialization.jl")
export ComprModeType, SEALHeader, load_header!

include("encryptionparams.jl")
export EncryptionParameters, SchemeType, poly_modulus_degree,
       set_poly_modulus_degree!, set_coeff_modulus!, coeff_modulus,
       scheme, plain_modulus, set_plain_modulus!, plain_modulus_batching, parms_id, save!,
       save_size, load!

include("context.jl")
export SEALContext, first_parms_id, last_parms_id, get_context_data, key_context_data,
       first_context_data, parameter_error_message, using_keyswitching
export ContextData, chain_index, parms, parms_id, total_coeff_modulus_bit_count, qualifiers,
       next_context_data
export EncryptionParameterQualifiers, using_batching

include("publickey.jl")
export PublicKey, parms_id

include("secretkey.jl")
export SecretKey, parms_id, save!, load!

include("galoiskeys.jl")
export GaloisKeys, parms_id

include("relinkeys.jl")
export RelinKeys, parms_id, save_size, save!, load!

include("keygenerator.jl")
export KeyGenerator, public_key, secret_key, relin_keys_local, relin_keys, galois_keys_local

include("plaintext.jl")
export Plaintext, scale, scale!, parms_id, to_string, save_size, save!

include("ciphertext.jl")
export Ciphertext, scale, scale!, parms_id, size, length, save_size, save!, load!, reserve!

include("encryptor.jl")
export Encryptor, encrypt!, encrypt_symmetric, encrypt_symmetric!

include("evaluator.jl")
export Evaluator, square!, square_inplace!, relinearize!, relinearize_inplace!, rescale_to_next!,
       rescale_to_next_inplace!, multiply_plain!, multiply_plain_inplace!, multiply!,
       multiply_inplace!, mod_switch_to!, mod_switch_to_inplace!, mod_switch_to_next!,
       mod_switch_to_next_inplace!, add!, add_inplace!, add_plain!, add_plain_inplace!,
       rotate_vector!, rotate_vector_inplace!, rotate_rows!, rotate_rows_inplace!,
       rotate_columns!, rotate_columns_inplace!, complex_conjugate!, complex_conjugate_inplace!,
       negate!

include("decryptor.jl")
export Decryptor, decrypt!, invariant_noise_budget

include("ckks.jl")
export CKKSEncoder, slot_count, encode!, decode!

include("intencoder.jl")
export IntegerEncoder, encode!, encode, decode_int32, plain_modulus

include("batchencoder.jl")
export BatchEncoder, slot_count, encode!, decode!

include("memorymanager.jl")
export MemoryPoolHandle, alloc_byte_count, memory_manager_get_pool


end
