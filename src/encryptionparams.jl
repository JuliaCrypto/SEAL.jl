
mutable struct EncryptionParameters
  handle::Ptr{Cvoid}

  function EncryptionParameters(scheme)
    handleptr = Ref{Ptr{Cvoid}}(0)
    ccall((:EncParams_Create1, seal_library_path), Clong,
          (UInt8, Ref{Ptr{Cvoid}}),
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

@enum SchemeType::UInt8 none=0 bfv=1 ckks=2

function get_poly_modulus_degree(ep)
  degree = Ref{UInt64}(0)
  ccall((:EncParams_GetPolyModulusDegree, seal_library_path), Clong,
        (Ptr{Cvoid},Ref{UInt64}),
        ep.handle, degree)
  return Int(degree[])
end

function set_poly_modulus_degree!(ep, degree)
  ccall((:EncParams_SetPolyModulusDegree, seal_library_path), Clong,
        (Ptr{Cvoid}, UInt64),
        ep.handle, degree)
  return nothing
end

function set_coeff_modulus!(ep, coeff_modulus)
  # FIXME: get  coeff_modulus length
  ccall((:EncParams_SetCoeffModulus, seal_library_path), Clong,
        (Ptr{Cvoid}, UInt64, Ptr{Ptr{Cvoid}}),
        ep.handle, length(coeff_modulus), coeff_modulus.handle)
  return nothing
end

