
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
    x = new(handle, context)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:CKKSEncoder_Destroy, libsealc), Clong, (Ptr{Cvoid},), x)
    end
    return x
  end
end

function slot_count(encoder::CKKSEncoder)
  count = Ref{UInt64}(0)
  retval = ccall((:CKKSEncoder_SlotCount, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt64}),
                 encoder, count)
  @check_return_value retval
  return Int(count[])
end

function encode!(destination, values::DenseVector{Float64}, scale, encoder::CKKSEncoder)
  value_count = UInt64(length(values))
  parms_id = first_parms_id(encoder.context)
  retval = ccall((:CKKSEncoder_Encode1, libsealc), Clong,
                 (Ptr{Cvoid}, UInt64, Ref{Cdouble}, Ref{UInt64}, Float64, Ptr{Cvoid}, Ptr{Cvoid}),
                 encoder, value_count, values, parms_id, scale, destination, C_NULL)
  @check_return_value retval
  return destination
end

function encode!(destination::Plaintext, value::Float64, scale, encoder::CKKSEncoder)
  parms_id = first_parms_id(encoder.context)
  retval = ccall((:CKKSEncoder_Encode3, libsealc), Clong,
                 (Ptr{Cvoid}, Float64, Ref{UInt64}, Float64, Ptr{Cvoid}, Ptr{Cvoid}),
                 encoder, value, parms_id, scale, destination, C_NULL)
  @check_return_value retval
  return destination
end

function decode!(destination::DenseVector{Float64}, plain::Plaintext, encoder::CKKSEncoder)
  value_count = UInt64(length(destination))
  retval = ccall((:CKKSEncoder_Decode1, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ref{UInt64}, Ref{Cdouble}, Ptr{Cvoid}),
                 encoder, plain, value_count, destination, C_NULL)
  @check_return_value retval
  return destination
end
