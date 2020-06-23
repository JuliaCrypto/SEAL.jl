
mutable struct Encryptor
  handle::Ptr{Cvoid}

  function Encryptor(context::SEALContext, public_key::PublicKey, secret_key::SecretKey)
    handleref = Ref{Ptr{Cvoid}}(0)
    retval = ccall((:Encryptor_Create, libsealc), Clong,
                   (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   context.handle, public_key.handle, secret_key.handle, handleref)
    check_return_value(retval)
    return Encryptor(handleref[])
  end

  function Encryptor(context::SEALContext, public_key::PublicKey)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:Encryptor_Create, libsealc), Clong,
                   (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   context.handle, public_key.handle, C_NULL, handleref)
    check_return_value(retval)
    return Encryptor(handleref[])
  end

  function Encryptor(context::SEALContext, secret_key::SecretKey)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:Encryptor_Create, libsealc), Clong,
                   (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   context.handle, C_NULL, secret_key.handle, handleref)
    check_return_value(retval)
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

function encrypt!(destination::Ciphertext, plain::Plaintext, encryptor::Encryptor)
  retval = ccall((:Encryptor_Encrypt, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                 encryptor.handle, plain.handle, destination.handle, C_NULL)
  check_return_value(retval)
  return destination
end

