
mutable struct CKKSEncoder
  handle::Ptr{Cvoid}

  function CKKSEncoder(context)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    ccall((:CKKSEncoder_Create, seal_library_path), Clong,
          (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
          context.handle, handleref)
    return CKKSEncoder(handleref[])
  end

  function CKKSEncoder(handle::Ptr{Cvoid})
    x = new(handle)
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
