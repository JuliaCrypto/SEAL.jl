
mutable struct PublicKey
  handle::Ptr{Cvoid}

  function PublicKey()
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:PublicKey_Create, libsealc), Clong,
                   (Ref{Ptr{Cvoid}},),
                   handleref)
    check_return_value(retval)
    return PublicKey(handleref[])
  end

  function PublicKey(handle::Ptr{Cvoid})
    x = new(handle)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:PublicKey_Destroy, libsealc), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end

