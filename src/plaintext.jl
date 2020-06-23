
mutable struct Plaintext <: SEALObject
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
      ccall((:Plaintext_Destroy, libsealc), Clong, (Ptr{Cvoid},), x)
    end
    return x
  end
end

function scale(plain::Plaintext)
  scale_ = Ref{Cdouble}(0)
  retval = ccall((:Plaintext_Scale, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{Cdouble}),
                 plain, scale_)
  @check_return_value retval
  return Float64(scale_[])
end
