
"""
    Ciphertext

A ciphertext element, consisting of two or more polynomials. It can be created from a `Plaintext`
element by encrypting it with an appropriate `Encryptor` instance. `Ciphertext` instances should
usually not be modified directly by the user but only through the corresponding functions of
`Evaluator`. Decryption is performed via a `Decryptor` instance, which converts a `Ciphertext` back
to a `Plaintext` instance.

See also: [`Plaintext`](@ref), [`Encryptor`](@ref), [`Decryptor`](@ref), [`Evaluator`](@ref)
"""
mutable struct Ciphertext <: SEALObject
  handle::Ptr{Cvoid}

  function Ciphertext()
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:Ciphertext_Create1, libsealc), Clong,
                   (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   C_NULL, handleref)
    @check_return_value retval
    return Ciphertext(handleref[])
  end

  function Ciphertext(context)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:Ciphertext_Create3, libsealc), Clong,
                   (Ptr{Cvoid}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   context, C_NULL, handleref)
    @check_return_value retval
    return Ciphertext(handleref[])
  end

  function Ciphertext(handle::Ptr{Cvoid})
    object = new(handle)
    finalizer(destroy, object)
    return object
  end
end

function destroy(object::Ciphertext)
  if isallocated(object)
    ccall((:Ciphertext_Destroy, libsealc), Clong, (Ptr{Cvoid},), object)
  end
end

function scale(encrypted::Ciphertext)
  value = Ref{Cdouble}(0)
  retval = ccall((:Ciphertext_Scale, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{Cdouble}),
                 encrypted, value)
  @check_return_value retval
  return Float64(value[])
end

function scale!(encrypted::Ciphertext, value::Float64)
  retval = ccall((:Ciphertext_SetScale, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{Cdouble}),
                 encrypted, value)
  @check_return_value retval
  return encrypted
end

function parms_id(encrypted::Ciphertext)
  parms_id_ = zeros(UInt64, 4)
  retval = ccall((:Ciphertext_ParmsId, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt64}),
                 encrypted, parms_id_)
  @check_return_value retval
  return parms_id_
end

function Base.size(encrypted::Ciphertext)
  sizeref = Ref{UInt64}(0)
  retval = ccall((:Ciphertext_Size, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt64}),
                 encrypted, sizeref)
  @check_return_value retval
  return (Int(sizeref[]),)
end
Base.length(encrypted::Ciphertext) = size(encrypted)[1]

function save_size(compr_mode, encrypted::Ciphertext)
  result = Ref{Int64}(0)
  retval = ccall((:Ciphertext_SaveSize, libsealc), Clong,
                 (Ptr{Cvoid}, UInt8, Ref{Int64}),
                 encrypted, compr_mode, result)
  @check_return_value retval
  return Int(result[])
end
save_size(encrypted::Ciphertext) = save_size(ComprModeType.default, encrypted)

function save!(buffer::DenseVector{UInt8}, length::Integer,
               compr_mode::ComprModeType.ComprModeTypeEnum, encrypted::Ciphertext)
  out_bytes = Ref{Int64}(0)
  retval = ccall((:Ciphertext_Save, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt8}, UInt64, UInt8, Ref{Int64}),
                 encrypted, buffer, length, compr_mode, out_bytes)
  @check_return_value retval
  return Int(out_bytes[])
end
function save!(buffer::DenseVector{UInt8}, length::Integer, encrypted::Ciphertext)
  return save!(buffer, length, ComprModeType.default, encrypted)
end
function save!(buffer::DenseVector{UInt8}, encrypted::Ciphertext)
  return save!(buffer, length(buffer), encrypted)
end

function load!(encrypted::Ciphertext, context::SEALContext, buffer::DenseVector{UInt8}, length)
  in_bytes = Ref{Int64}(0)
  retval = ccall((:Ciphertext_Load, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ref{UInt8}, UInt64, Ref{Int64}),
                 encrypted, context, buffer, length, in_bytes)
  @check_return_value retval
  return Int(in_bytes[])
end
function load!(encrypted::Ciphertext, context::SEALContext, buffer::DenseVector{UInt8})
  return load!(encrypted, context, buffer, length(buffer))
end

function reserve!(encrypted::Ciphertext, capacity)
  retval = ccall((:Ciphertext_Reserve3, libsealc), Clong,
                 (Ptr{Cvoid}, UInt64),
                 encrypted, capacity)
  @check_return_value retval
  return encrypted
end

