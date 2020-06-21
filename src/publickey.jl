
mutable struct PublicKey
  handle::Ptr{Cvoid}

  function PublicKey()
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    ccall((:PublicKey_Create, seal_library_path), Clong,
          (Ref{Ptr{Cvoid}},),
          handleref)
    return PublicKey(handleref[])
  end

  function PublicKey(handle::Ptr{Cvoid})
    x = new(handle)
    finalizer(x) do x
      @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:PublicKey_Destroy, seal_library_path), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end

