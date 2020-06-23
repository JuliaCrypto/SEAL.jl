
mutable struct Plaintext
  handle::Ptr{Cvoid}

  function Plaintext()
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:Plaintext_Create1, libsealc), Clong,
                   (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   C_NULL, handleref)
    @check_return_value retval
    return Plaintext(handleref[])
  end

  function Plaintext(handle::Ptr{Cvoid})
    x = new(handle)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:Plaintext_Destroy, libsealc), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end
