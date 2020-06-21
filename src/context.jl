
mutable struct SEALContext
  handle::Ptr{Cvoid}

  function SEALContext(enc_param; expand_mod_chain=true, sec_level=SecLevelType.tc128)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    ccall((:SEALContext_Create, seal_library_path), Clong,
          (Ptr{Cvoid}, UInt8, Int32, Ref{Ptr{Cvoid}}),
          enc_param.handle, expand_mod_chain, sec_level, handleref)
    x = new(handleref[])
    finalizer(x) do x
      @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:SEALContext_Destroy, seal_library_path), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end

