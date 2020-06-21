
mutable struct SecretKey
  handle::Ptr{Cvoid}

  function SecretKey()
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    ccall((:SecretKey_Create, seal_library_path), Clong,
          (Ref{Ptr{Cvoid}},),
          handleref)
    return SecretKey(handleref[])
  end

  function SecretKey(handle::Ptr{Cvoid})
    x = new(handle)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:SecretKey_Destroy, seal_library_path), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end

