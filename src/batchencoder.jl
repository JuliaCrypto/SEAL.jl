
mutable struct BatchEncoder <: SEALObject
  handle::Ptr{Cvoid}
  context::SEALContext

  function BatchEncoder(context)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:BatchEncoder_Create, libsealc), Clong,
                   (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   context, handleref)
    @check_return_value retval
    return BatchEncoder(handleref[], context)
  end

  function BatchEncoder(handle::Ptr{Cvoid}, context)
    object = new(handle, context)
    finalizer(destroy!, object)
    return object
  end
end

function destroy!(object::BatchEncoder)
  if isallocated(object)
    @check_return_value ccall((:BatchEncoder_Destroy, libsealc), Clong, (Ptr{Cvoid},), object)
    sethandle!(object, C_NULL)
  end

  return nothing
end

function slot_count(encoder::BatchEncoder)
  count = Ref{UInt64}(0)
  retval = ccall((:BatchEncoder_GetSlotCount, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt64}),
                 encoder, count)
  @check_return_value retval
  return Int(count[])
end

function encode!(destination::Plaintext, values::DenseArray{UInt64}, encoder::BatchEncoder)
  retval = ccall((:BatchEncoder_Encode1, libsealc), Clong,
                 (Ptr{Cvoid}, UInt64, Ref{UInt64}, Ptr{Cvoid}),
                 encoder, length(values), values, destination)
  @check_return_value retval
  return destination
end

function encode!(destination::Plaintext, values::DenseArray{Int64}, encoder::BatchEncoder)
  retval = ccall((:BatchEncoder_Encode2, libsealc), Clong,
                 (Ptr{Cvoid}, UInt64, Ref{Int64}, Ptr{Cvoid}),
                 encoder, length(values), values, destination)
  @check_return_value retval
  return destination
end

function decode!(destination::DenseVector{UInt64}, plain::Plaintext, encoder::BatchEncoder)
  count = Ref{UInt64}(0)
  retval = ccall((:BatchEncoder_Decode1, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ref{UInt64}, Ref{UInt64}, Ptr{Cvoid}),
                 encoder, plain, count, destination, C_NULL)
  @check_return_value retval
  return destination
end

function decode!(destination::DenseVector{Int64}, plain::Plaintext, encoder::BatchEncoder)
  count = Ref{UInt64}(0)
  retval = ccall((:BatchEncoder_Decode2, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ref{UInt64}, Ref{Int64}, Ptr{Cvoid}),
                 encoder, plain, count, destination, C_NULL)
  @check_return_value retval
  return destination
end
