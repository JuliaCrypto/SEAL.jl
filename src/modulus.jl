
"""
    Modulus

Represents a non-negative integer modulus of up to 61 bits, e.g., for the plain modulus and the
coefficient modulus in instances of `EncryptionParameters`.

See also: [`EncryptionParameters`](@ref)
"""
mutable struct Modulus <: SEALObject
  handle::Ptr{Cvoid}

  function Modulus(value::Integer)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:Modulus_Create1, libsealc), Clong,
                   (UInt8, Ref{Ptr{Cvoid}}),
                   value, handleref)
    @check_return_value retval
    return Modulus(handleref[])
  end

  function Modulus(handle::Ptr{Cvoid}; destroy_on_gc=true)
    x = new(handle)
    if destroy_on_gc
      finalizer(x) do x
        # @async println("Finalizing $x at line $(@__LINE__).")
        ccall((:Modulus_Destroy, libsealc), Clong, (Ptr{Cvoid},), x)
      end
    end
    return x
  end
end

module SecLevelType
@enum SecLevelTypeEnum::Cint none=0 tc128=128 tc192=192 tc256=256
end

function bit_count(modulus::Modulus)
  bit_count = Ref{Cint}(0)
  retval = ccall((:Modulus_BitCount, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{Cint}),
                 modulus, bit_count)
  @check_return_value retval
  return Int(bit_count[])
end

function value(modulus::Modulus)
  value = Ref{UInt64}(0)
  retval = ccall((:Modulus_Value, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt64}),
                 modulus, value)
  @check_return_value retval
  return Int(value[])
end

function coeff_modulus_create(poly_modulus_degree, bit_sizes)
  modulusptrs = Vector{Ptr{Cvoid}}(undef, length(bit_sizes))
  retval = ccall((:CoeffModulus_Create, libsealc), Clong,
                 (UInt64, UInt64, Ref{Cint}, Ref{Ptr{Cvoid}}),
                 poly_modulus_degree, length(bit_sizes), collect(Cint, bit_sizes), modulusptrs)
  @check_return_value retval
  modulus = Modulus[Modulus(modulusptrs[i]) for i in 1:length(bit_sizes)]
  return modulus
end

function coeff_modulus_bfv_default(poly_modulus_degree, sec_level=SecLevelType.tc128)
  len = Ref{UInt64}(0)

  # First call to obtain length (modulus result pointer is null)
  retval = ccall((:CoeffModulus_BFVDefault, libsealc), Clong,
                 (UInt64, Cint, Ref{UInt64}, Ptr{Ptr{Cvoid}}),
                 poly_modulus_degree, sec_level, len, C_NULL)
  @check_return_value retval

  # Second call to obtain modulus
  modulusptrs = Vector{Ptr{Cvoid}}(undef, len[])
  retval = ccall((:CoeffModulus_BFVDefault, libsealc), Clong,
                 (UInt64, Cint, Ref{UInt64}, Ref{Ptr{Cvoid}}),
                 poly_modulus_degree, sec_level, len, modulusptrs)
  @check_return_value retval

  modulus = Modulus[Modulus(ptr) for ptr in modulusptrs]
  return modulus
end

function plain_modulus_batching(poly_modulus_degree, bit_size)
  return coeff_modulus_create(poly_modulus_degree, [bit_size])[1]
end
