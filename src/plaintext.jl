
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
  value = Ref{Cdouble}(0)
  retval = ccall((:Plaintext_Scale, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{Cdouble}),
                 plain, value)
  @check_return_value retval
  return Float64(value[])
end

function scale!(plain::Plaintext, value::Float64)
  retval = ccall((:Plaintext_SetScale, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{Cdouble}),
                 plain, value)
  @check_return_value retval
  return plain
end

function parms_id(plain::Plaintext)
  parms_id_ = zeros(UInt64, 4)
  retval = ccall((:Plaintext_GetParmsId, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt64}),
                 plain, parms_id_)
  @check_return_value retval
  return parms_id_
end

