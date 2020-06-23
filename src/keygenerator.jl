
mutable struct KeyGenerator
  handle::Ptr{Cvoid}

  function KeyGenerator(context::SEALContext)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    ccall((:KeyGenerator_Create1, libsealc), Clong,
          (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
          context.handle, handleref)
    return KeyGenerator(handleref[])
  end

  function KeyGenerator(handle::Ptr{Cvoid})
    x = new(handle)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:KeyGenerator_Destroy, libsealc), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end

function public_key(keygen::KeyGenerator)
  keyptr = Ref{Ptr{Cvoid}}(C_NULL)
  ccall((:KeyGenerator_PublicKey, libsealc), Clong,
        (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
        keygen.handle, keyptr)
  return PublicKey(keyptr[])
end

function secret_key(keygen::KeyGenerator)
  keyptr = Ref{Ptr{Cvoid}}(C_NULL)
  ccall((:KeyGenerator_SecretKey, libsealc), Clong,
        (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
        keygen.handle, keyptr)
  return SecretKey(keyptr[])
end

function relin_keys_local(keygen::KeyGenerator)
  keyptr = Ref{Ptr{Cvoid}}(C_NULL)
  ccall((:KeyGenerator_RelinKeys, libsealc), Clong,
        (Ptr{Cvoid}, UInt8, Ref{Ptr{Cvoid}}),
        keygen.handle, false, keyptr)
  return RelinKeys(keyptr[])
end

function relin_keys(keygen::KeyGenerator)
  keyptr = Ref{Ptr{Cvoid}}(C_NULL)
  ccall((:KeyGenerator_RelinKeys, libsealc), Clong,
        (Ptr{Cvoid}, UInt8, Ref{Ptr{Cvoid}}),
        keygen.handle, true, keyptr)
  return RelinKeys(keyptr[])
end
