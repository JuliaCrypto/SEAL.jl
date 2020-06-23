
mutable struct RelinKeys
  handle::Ptr{Cvoid}

  function RelinKeys()
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    # RelinKeys are created as KSwitchKeys since they share the same data
    retval = ccall((:KSwitchKeys_Create1, libsealc), Clong,
                   (Ref{Ptr{Cvoid}},),
                   handleref)
    @check_return_value retval
    return RelinKeys(handleref[])
  end

  function RelinKeys(handle::Ptr{Cvoid})
    x = new(handle)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:KSwitchKeys_Destroy, libsealc), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end

