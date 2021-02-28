
mutable struct IntegerEncoder <: SEALObject
  handle::Ptr{Cvoid}
  context::SEALContext

  function IntegerEncoder(context)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:IntegerEncoder_Create, libsealc), Clong,
                   (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   context, handleref)
    @check_return_value retval
    return IntegerEncoder(handleref[], context)
  end

  function IntegerEncoder(handle::Ptr{Cvoid}, context)
    object = new(handle, context)
    finalizer(destroy, object)
    return object
  end
end

function destroy(object::IntegerEncoder)
  if isallocated(object)
    ccall((:IntegerEncoder_Destroy, libsealc), Clong, (Ptr{Cvoid},), object)
  end
end

function encode!(destination::Plaintext, value::Int32, encoder::IntegerEncoder)
  retval = ccall((:IntegerEncoder_Encode1, libsealc), Clong,
                 (Ptr{Cvoid}, Int32, Ptr{Cvoid}),
                 encoder, value, destination)
  @check_return_value retval
  return destination
end

function encode!(destination::Plaintext, value::UInt32, encoder::IntegerEncoder)
  retval = ccall((:IntegerEncoder_Encode2, libsealc), Clong,
                 (Ptr{Cvoid}, UInt32, Ptr{Cvoid}),
                 encoder, value, destination)
  @check_return_value retval
  return destination
end

function encode!(destination::Plaintext, value::UInt64, encoder::IntegerEncoder)
  retval = ccall((:IntegerEncoder_Encode3, libsealc), Clong,
                 (Ptr{Cvoid}, UInt64, Ptr{Cvoid}),
                 encoder, value, destination)
  @check_return_value retval
  return destination
end

function encode!(destination::Plaintext, value::Int64, encoder::IntegerEncoder)
  retval = ccall((:IntegerEncoder_Encode4, libsealc), Clong,
                 (Ptr{Cvoid}, Int64, Ptr{Cvoid}),
                 encoder, value, destination)
  @check_return_value retval
  return destination
end

function encode(value, encoder::IntegerEncoder)
  p = Plaintext()
  encode!(p, value, encoder)
  return p
end

function decode_int32(plain::Plaintext, encoder::IntegerEncoder)
  result = Ref{Int32}(0)
  retval = ccall((:IntegerEncoder_DecodeInt32, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ref{Int32}),
                 encoder, plain, result)
  @check_return_value retval
  return Int(result[])
end

function plain_modulus(encoder::IntegerEncoder)
  handleref = Ref{Ptr{Cvoid}}(C_NULL)
  retval = ccall((:IntegerEncoder_PlainModulus, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                 encoder, handleref)
  @check_return_value retval
  return Modulus(handleref[])
end
