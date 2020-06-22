
mutable struct Encryptor
  handle::Ptr{Cvoid}

  function Encryptor(context, public_key::PublicKey, secret_key::SecretKey)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    ccall((:Encryptor_Create, libsealc), Clong,
          (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
          context.handle, public_key.handle, secret_key.handle, handleref)
    return Encryptor(handleref[])
  end

  function Encryptor(context, public_key::PublicKey)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    ccall((:Encryptor_Create, libsealc), Clong,
          (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
          context.handle, public_key.handle, Ptr{Cvoid}(C_NULL), handleref)
    return Encryptor(handleref[])
  end

  function Encryptor(context, secret_key::SecretKey)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    ccall((:Encryptor_Create, libsealc), Clong,
          (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
          context.handle, Ptr{Cvoid}(C_NULL), secret_key.handle, handleref)
    return Encryptor(handleref[])
  end

  function Encryptor(handle::Ptr{Cvoid})
    x = new(handle)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:Encryptor_Destroy, libsealc), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end

function encrypt!(destination, plain, encryptor::Encryptor)
  ccall((:Encryptor_Encrypt, libsealc), Clong,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
        encryptor.handle, plaintext.handle, destination.handle, destination.memory_pool_handle.handle)
  return destination
end

