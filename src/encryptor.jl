
"""
    Encryptor

An `Encryptor` can be used to encrypt a `Plaintext` instance, yielding a `Ciphertext` instance.

See also: [`Plaintext`](@ref), [`Ciphertext`](@ref)
"""
mutable struct Encryptor <: SEALObject
  handle::Ptr{Cvoid}

  function Encryptor(context::SEALContext, public_key::PublicKey, secret_key::SecretKey)
    handleref = Ref{Ptr{Cvoid}}(0)
    retval = ccall((:Encryptor_Create, libsealc), Clong,
                   (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   context, public_key, secret_key, handleref)
    @check_return_value retval
    return Encryptor(handleref[])
  end

  function Encryptor(context::SEALContext, public_key::PublicKey)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:Encryptor_Create, libsealc), Clong,
                   (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   context, public_key, C_NULL, handleref)
    @check_return_value retval
    return Encryptor(handleref[])
  end

  function Encryptor(context::SEALContext, secret_key::SecretKey)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:Encryptor_Create, libsealc), Clong,
                   (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   context, C_NULL, secret_key, handleref)
    @check_return_value retval
    return Encryptor(handleref[])
  end

  function Encryptor(handle::Ptr{Cvoid})
    object = new(handle)
    finalizer(destroy, object)
    return object
  end
end

function destroy(object::Encryptor)
  if isallocated(object)
    ccall((:Encryptor_Destroy, libsealc), Clong, (Ptr{Cvoid},), object)
  end
end

function set_secret_key!(encryptor::Encryptor, secret_key::SecretKey)
  retval = ccall((:Encryptor_SetSecretKey, libsealc), Clong,
                  (Ptr{Cvoid}, Ptr{Cvoid}),
                  encryptor, secret_key)
  @check_return_value retval
  return nothing
end

function encrypt!(destination::Ciphertext, plain::Plaintext, encryptor::Encryptor)
  retval = ccall((:Encryptor_Encrypt, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                 encryptor, plain, destination, C_NULL)
  @check_return_value retval
  return destination
end

function encrypt_symmetric!(destination::Ciphertext, plain::Plaintext, encryptor::Encryptor)
  retval = ccall((:Encryptor_EncryptSymmetric, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, UInt8, Ptr{Cvoid}, Ptr{Cvoid}),
                 encryptor, plain, false, destination, C_NULL)
  @check_return_value retval
  return destination
end
function encrypt_symmetric(plain::Plaintext, encryptor::Encryptor)
  destination = Ciphertext()
  retval = ccall((:Encryptor_EncryptSymmetric, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, UInt8, Ptr{Cvoid}, Ptr{Cvoid}),
                 encryptor, plain, true, destination, C_NULL)
  @check_return_value retval
  return destination
end

