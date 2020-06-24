
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

  function Ciphertext(handle::Ptr{Cvoid})
    x = new(handle)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:Ciphertext_Destroy, libsealc), Clong, (Ptr{Cvoid},), x)
    end
    return x
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

