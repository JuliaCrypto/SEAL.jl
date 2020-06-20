
mutable struct EncryptionParameters
  handle::Ptr{Cvoid}

  function EncryptionParameters(scheme)
    handleref = Ref{Ptr{Cvoid}}(0)
    ccall((:EncParams_Create1, seal_library_path), Clong,
          (UInt8, Ref{Ptr{Cvoid}}),
          scheme, handleref)
    x = new(handleref[])
    finalizer(x) do x
      @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:EncParams_Destroy, seal_library_path), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end

@enum SchemeType::UInt8 none=0 bfv=1 ckks=2

function get_poly_modulus_degree(enc_param)
  degree = Ref{UInt64}(0)
  ccall((:EncParams_GetPolyModulusDegree, seal_library_path), Clong,
        (Ptr{Cvoid}, Ref{UInt64}),
        enc_param.handle, degree)
  return Int(degree[])
end

function set_poly_modulus_degree!(enc_param, degree)
  ccall((:EncParams_SetPolyModulusDegree, seal_library_path), Clong,
        (Ptr{Cvoid}, UInt64),
        enc_param.handle, degree)
  return nothing
end

function set_coeff_modulus!(enc_param, coeff_modulus)
  coeff_modulus_ptrs = Ptr{Cvoid}[cm.handle for cm in coeff_modulus]
  ccall((:EncParams_SetCoeffModulus, seal_library_path), Clong,
        (Ptr{Cvoid}, UInt64, Ptr{Ptr{Cvoid}}),
        enc_param.handle, length(coeff_modulus), coeff_modulus_ptrs)
  return nothing
end

function coeff_modulus(enc_param)
  length = Ref{UInt64}(0)
  modulusptr = Ref{Ptr{Cvoid}}(0)
  ccall((:EncParams_GetCoeffModulus, seal_library_path), Clong,
        (Ptr{Cvoid}, Ref{UInt64}, Ref{Ptr{Cvoid}}),
        enc_param.handle, length, modulusptr)
  @show modulusptr
  @show modulusptr[]
  modulus = Modulus[Modulus(unsafe_load(modulusptr[], i)) for i in 1:length[]]
  return modulus
end

