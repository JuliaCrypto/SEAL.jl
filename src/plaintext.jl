
mutable struct Plaintext
  handle::Ptr{Cvoid}

  function Plaintext()
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    ccall((:Plaintext_Create1, libsealc), Clong,
          (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
          C_NULL, handleref)
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
