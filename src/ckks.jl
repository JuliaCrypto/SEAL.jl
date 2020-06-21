
mutable struct CKKSEncoder
  handle::Ptr{Cvoid}
  context::SEALContext

  function CKKSEncoder(context)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    ccall((:CKKSEncoder_Create, seal_library_path), Clong,
          (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
          context.handle, handleref)
    return CKKSEncoder(handleref[], context)
  end

  function CKKSEncoder(handle::Ptr{Cvoid}, context)
    x = new(handle, context)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:CKKSEncoder_Destroy, seal_library_path), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end

function slot_count(encoder::CKKSEncoder)
  count = Ref{UInt64}(0)
  ccall((:CKKSEncoder_SlotCount, seal_library_path), Clong,
        (Ptr{Cvoid}, Ref{UInt64}),
        encoder.handle, count)
  return Int(count[])
end

function encode!(destination, value::Float64, scale, encoder::CKKSEncoder)
  parms_id = Ref{UInt64}(first_parms_id(encoder.context))
  ccall((:CKKSEncoder_Encode3, seal_library_path), Clong,
        (Ptr{Cvoid}, Float64, Ref{UInt64}, Float64, Ptr{Cvoid}, Ptr{Cvoid}),
        encoder.handle, value, parms_id, scale, destination.handle, destination.memory_pool_handle.handle)
  return destination
end
