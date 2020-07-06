
"""
    Plaintext

A plaintext element, storing data as a polynomial modulo the plaintext modulus. It can be used to
create a `Ciphertext` element by encrypting it with an appropriate `Encryptor` instance. Decrypting
a `Ciphertext` with a `Decryptor` instance will again return a `Plaintext` instance.

See also: [`Ciphertext`](@ref), [`Encryptor`](@ref), [`Decryptor`](@ref)
"""
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

  function Plaintext(capacity, coeff_count)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:Plaintext_Create3, libsealc), Clong,
                   (UInt64, UInt64, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   capacity, coeff_count, C_NULL, handleref)
    @check_return_value retval
    return Plaintext(handleref[])
  end

  function Plaintext(hex_poly)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:Plaintext_Create4, libsealc), Clong,
                   (Cstring, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   hex_poly, C_NULL, handleref)
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

function to_string(plain::Plaintext)
  len = Ref{UInt64}(0)

  # First call to obtain length (message pointer is null)
  retval = ccall((:Plaintext_ToString, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{UInt8}, Ref{UInt64}),
                 plain, C_NULL, len)
  @check_return_value retval

  # Second call to obtain message
  # Note: The "+1" is needed since the terminating NULL byte is included in the *copy* operation in
  # SEAL, but *not* in the returned length.
  message = Vector{UInt8}(undef, len[] + 1)
  retval = ccall((:Plaintext_ToString, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{UInt8}, Ref{UInt64}),
                 plain, message, len)
  @check_return_value retval

  # Return as String but without terminating NULL byte
  return String(message[1:end-1])
end

function save_size(compr_mode, plain::Plaintext)
  result = Ref{Int64}(0)
  retval = ccall((:Plaintext_SaveSize, libsealc), Clong,
                 (Ptr{Cvoid}, UInt8, Ref{Int64}),
                 plain, compr_mode, result)
  @check_return_value retval
  return Int(result[])
end
save_size(plain::Plaintext) = save_size(ComprModeType.default, plain)

function save!(buffer::DenseVector{UInt8}, length::Integer,
               compr_mode::ComprModeType.ComprModeTypeEnum, plain::Plaintext)
  out_bytes = Ref{Int64}(0)
  retval = ccall((:Plaintext_Save, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt8}, UInt64, UInt8, Ref{Int64}),
                 plain, buffer, length, compr_mode, out_bytes)
  @check_return_value retval
  return Int(out_bytes[])
end
function save!(buffer::DenseVector{UInt8}, length::Integer, plain::Plaintext)
  return save!(buffer, length, ComprModeType.default, plain)
end
function save!(buffer::DenseVector{UInt8}, plain::Plaintext)
  return save!(buffer, length(buffer), plain)
end

function Base.:(==)(plain1::Plaintext, plain2::Plaintext)
  result = Ref{UInt8}(0)
  retval = ccall((:Plaintext_Equals, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ref{UInt8}),
                 plain1, plain2, result)
  @check_return_value retval
  return Bool(result[])
end
