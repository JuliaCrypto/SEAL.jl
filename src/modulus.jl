
mutable struct Modulus
  handle::Ptr{Cvoid}

  function Modulus(value::Integer)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    ccall((:Modulus_Create1, libsealc), Clong,
          (UInt8, Ref{Ptr{Cvoid}}),
          scheme, handleref)
    return Modulus(handleref[])
  end

  function Modulus(handle::Ptr{Cvoid})
    x = new(handle)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:Modulus_Destroy, libsealc), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end

module SecLevelType
@enum SecLevelTypeEnum::Cint none=0 tc128=128 tc192=192 tc256=256
end

function bit_count(modulus::Modulus)
  bit_count = Ref{Cint}(0)
  ccall((:Modulus_BitCount, libsealc), Clong,
        (Ptr{Cvoid}, Ref{Cint}),
        modulus.handle, bit_count)
  return Int(bit_count[])
end

function value(modulus::Modulus)
  value = Ref{UInt64}(0)
  ccall((:Modulus_Value, libsealc), Clong,
        (Ptr{Cvoid}, Ref{UInt64}),
        modulus.handle, value)
  return Int(value[])
end

function coeff_modulus_create(poly_modulus_degree, bit_sizes)
  modulusptrs = Vector{Ptr{Cvoid}}(undef, length(bit_sizes))
  ccall((:CoeffModulus_Create, libsealc), Clong,
        (UInt64, UInt64, Ref{Cint}, Ref{Ptr{Cvoid}}),
        poly_modulus_degree, length(bit_sizes), collect(Cint, bit_sizes), modulusptrs)
  modulus = Modulus[Modulus(modulusptrs[i]) for i in 1:length(bit_sizes)]
  return modulus
end
