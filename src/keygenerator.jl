
mutable struct KeyGenerator
  handle::Ptr{Cvoid}

  function KeyGenerator(context)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    ccall((:KeyGenerator_Create1, seal_library_path), Clong,
          (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
          context.handle, handleref)
    return KeyGenerator(handleref[])
  end

  function KeyGenerator(handle::Ptr{Cvoid})
    x = new(handle)
    finalizer(x) do x
      @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:KeyGenerator_Destroy, seal_library_path), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end

function public_key(keygen::KeyGenerator)
  keyptr = Ref{Ptr{Cvoid}}(C_NULL)
  ccall((:KeyGenerator_PublicKey, seal_library_path), Clong,
        (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
        keygen.handle, keyptr)
  return PublicKey(keyptr[])
end

function secret_key(keygen::KeyGenerator)
  keyptr = Ref{Ptr{Cvoid}}(C_NULL)
  ccall((:KeyGenerator_SecretKey, seal_library_path), Clong,
        (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
        keygen.handle, keyptr)
  return SecretKey(keyptr[])
end
