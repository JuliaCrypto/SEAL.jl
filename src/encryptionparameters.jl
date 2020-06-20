
mutable struct EncryptionParameters
  handle::Ptr{Cvoid}

  function EncryptionParameters(scheme)
    handleptr = Ptr{Ptr{Cvoid}}(0)
    ccall((:EncParams_Create1, seal_library_path), Clong,
          (UInt8, Ptr{Ptr{Cvoid}}),
          scheme, handleptr)
    x = new(handleptr[])
    finalizer(x) do x
      ccall((:EncParams_Destroy, seal_library_path), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end

function get_poly_modulus_degree(ep)
  degree = Ref{UInt64}(0)
  ccall((:EncParams_GetPolyModulusDegree, seal_library_path), Clong,
        (Ptr{Cvoid},Ref{UInt64}),
        ep.handle, degree)
  return degree[]
end

function set_poly_modulus_degree!(ep, degree)
  ccall((:EncParams_SetPolyModulusDegree, seal_library_path), Clong,
        (Ptr{Cvoid}, UInt64),
        ep.handle, degree)
  return nothing
end
