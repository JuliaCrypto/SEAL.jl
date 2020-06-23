
mutable struct SEALContext
  handle::Ptr{Cvoid}

  function SEALContext(enc_param::EncryptionParameters; expand_mod_chain=true, sec_level=SecLevelType.tc128)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:SEALContext_Create, libsealc), Clong,
                   (Ptr{Cvoid}, UInt8, Cint, Ref{Ptr{Cvoid}}),
                   enc_param.handle, expand_mod_chain, sec_level, handleref)
    @check_return_value retval
    x = new(handleref[])
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:SEALContext_Destroy, libsealc), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end

function first_parms_id(context::SEALContext)
  parms_id = zeros(UInt64, 4)
  retval = ccall((:SEALContext_FirstParmsId, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt64}),
                 context.handle, parms_id)
  @check_return_value retval
  return parms_id
end
