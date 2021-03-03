
"""
    KeyGenerator

Can be used to generate a pair of matching secret and public keys. In addition, the `KeyGenerator`
provides functions to obtain relinearization keys (required after multiplication) and Galois keys
(needed for rotation).

See also: [`SecretKey`](@ref), [`PublicKey`](@ref), [`RelinKeys`](@ref)
"""
mutable struct KeyGenerator <: SEALObject
  handle::Ptr{Cvoid}

  function KeyGenerator(context::SEALContext)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:KeyGenerator_Create1, libsealc), Clong,
                   (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   context, handleref)
    @check_return_value retval
    return KeyGenerator(handleref[])
  end

  function KeyGenerator(handle::Ptr{Cvoid})
    object = new(handle)
    finalizer(destroy!, object)
    return object
  end
end

function destroy!(object::KeyGenerator)
  if isallocated(object)
    @check_return_value ccall((:KeyGenerator_Destroy, libsealc), Clong, (Ptr{Cvoid},), object)
    sethandle!(object, C_NULL)
  end

  return nothing
end

function create_public_key!(destination::PublicKey, keygen::KeyGenerator)
  keyptr = Ref{Ptr{Cvoid}}(C_NULL)
  retval = ccall((:KeyGenerator_CreatePublicKey, libsealc), Clong,
                 (Ptr{Cvoid}, UInt8, Ref{Ptr{Cvoid}}),
                 keygen, false, keyptr)
  @check_return_value retval

  # Destroy previous key and reuse its container
  destroy!(destination)
  sethandle!(destination, keyptr[])

  return nothing
end

function create_public_key(keygen::KeyGenerator)
  keyptr = Ref{Ptr{Cvoid}}(C_NULL)
  retval = ccall((:KeyGenerator_CreatePublicKey, libsealc), Clong,
                 (Ptr{Cvoid}, UInt8, Ref{Ptr{Cvoid}}),
                 keygen, true, keyptr)
  @check_return_value retval
  return PublicKey(keyptr[])
end

function secret_key(keygen::KeyGenerator)
  keyptr = Ref{Ptr{Cvoid}}(C_NULL)
  retval = ccall((:KeyGenerator_SecretKey, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                 keygen, keyptr)
  @check_return_value retval
  return SecretKey(keyptr[])
end

function create_relin_keys!(destination::RelinKeys, keygen::KeyGenerator)
  keyptr = Ref{Ptr{Cvoid}}(C_NULL)
  retval = ccall((:KeyGenerator_CreateRelinKeys, libsealc), Clong,
                 (Ptr{Cvoid}, UInt8, Ref{Ptr{Cvoid}}),
                 keygen, false, keyptr)
  @check_return_value retval

  # Destroy previous key and reuse its container
  destroy!(destination)
  sethandle!(destination, keyptr[])

  return nothing
end

function create_relin_keys(keygen::KeyGenerator)
  keyptr = Ref{Ptr{Cvoid}}(C_NULL)
  retval = ccall((:KeyGenerator_CreateRelinKeys, libsealc), Clong,
                 (Ptr{Cvoid}, UInt8, Ref{Ptr{Cvoid}}),
                 keygen, true, keyptr)
  @check_return_value retval
  return RelinKeys(keyptr[])
end

function create_galois_keys!(destination::GaloisKeys, keygen::KeyGenerator)
  keyptr = Ref{Ptr{Cvoid}}(C_NULL)
  retval = ccall((:KeyGenerator_CreateGaloisKeysAll, libsealc), Clong,
                 (Ptr{Cvoid}, UInt8, Ref{Ptr{Cvoid}}),
                 keygen, false, keyptr)
  @check_return_value retval

  # Destroy previous key and reuse its container
  destroy!(destination)
  sethandle!(destination, keyptr[])

  return nothing
end
