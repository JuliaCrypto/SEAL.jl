
"""
    CKKSEncoder

A `CKKSEncoder` provides functionality to convert raw data such as scalars and vectors into
`Plaintext` instances using `encode!`, and to convert `Plaintext` elements back to raw data using
`decode!`.

See also: [`Plaintext`](@ref), [`encode!`](@ref), [`decode!`](@ref)
"""
mutable struct CKKSEncoder <: SEALObject
  handle::Ptr{Cvoid}
  context::SEALContext

  function CKKSEncoder(context)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:CKKSEncoder_Create, libsealc), Clong,
                   (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   context, handleref)
    @check_return_value retval
    return CKKSEncoder(handleref[], context)
  end

  function CKKSEncoder(handle::Ptr{Cvoid}, context)
    object = new(handle, context)
    finalizer(destroy, object)
    return object
  end
end

function destroy(object::CKKSEncoder)
  if isallocated(object)
    ccall((:CKKSEncoder_Destroy, libsealc), Clong, (Ptr{Cvoid},), object)
  end
end

"""
    slot_count(encoder)

Return the number of available slots for a given encoder, i.e., how many raw data values can be
stored and processed simultaneously with the given encryption setup.
"""
function slot_count(encoder::CKKSEncoder)
  count = Ref{UInt64}(0)
  retval = ccall((:CKKSEncoder_SlotCount, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt64}),
                 encoder, count)
  @check_return_value retval
  return Int(count[])
end

"""
    encode!(destination, data::DenseVector{Float64}, scale, encoder)
    encode!(destination, data::Float64, scale, encoder)

Use `CKKSEncoder` instance `encoder` to encode raw `data`, which can either be a scalar or a dense
vector. The result is stored in the `Plaintext` instance `destination` using encoding precision
`scale`. Note that if `data` is a vector, it must have at least as many elements as there are slots
available.

See also: [`slot_count`](@ref)
"""
function encode! end

function encode!(destination::Plaintext, data::DenseVector{Float64}, scale, encoder::CKKSEncoder)
  value_count = UInt64(length(data))
  parms_id = first_parms_id(encoder.context)
  retval = ccall((:CKKSEncoder_Encode1, libsealc), Clong,
                 (Ptr{Cvoid}, UInt64, Ref{Cdouble}, Ref{UInt64}, Float64, Ptr{Cvoid}, Ptr{Cvoid}),
                 encoder, value_count, data, parms_id, scale, destination, C_NULL)
  @check_return_value retval
  return destination
end

function encode!(destination::Plaintext, data::Float64, scale, encoder::CKKSEncoder)
  parms_id = first_parms_id(encoder.context)
  retval = ccall((:CKKSEncoder_Encode3, libsealc), Clong,
                 (Ptr{Cvoid}, Float64, Ref{UInt64}, Float64, Ptr{Cvoid}, Ptr{Cvoid}),
                 encoder, data, parms_id, scale, destination, C_NULL)
  @check_return_value retval
  return destination
end

function encode!(destination::Plaintext, data::Integer, encoder::CKKSEncoder)
  parms_id = first_parms_id(encoder.context)
  retval = ccall((:CKKSEncoder_Encode5, libsealc), Clong,
                 (Ptr{Cvoid}, Int64, Ref{UInt64}, Ptr{Cvoid}),
                 encoder, data, parms_id, destination)
  @check_return_value retval
  return destination
end

"""
    decode!(destination, plain, encoder)

Use `CKKSEncoder` instance `encoder` to convert the `Plaintext` instance `plain` back to raw data.
The result is stored in the dense vector `destination`, which must have at least as many elements as
there are slots available.

See also: [`slot_count`](@ref)
"""
function decode!(destination::DenseVector{Float64}, plain::Plaintext, encoder::CKKSEncoder)
  value_count = UInt64(length(destination))
  retval = ccall((:CKKSEncoder_Decode1, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ref{UInt64}, Ref{Cdouble}, Ptr{Cvoid}),
                 encoder, plain, value_count, destination, C_NULL)
  @check_return_value retval
  return destination
end
