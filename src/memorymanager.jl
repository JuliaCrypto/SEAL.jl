
mutable struct MemoryPoolHandle <: SEALObject
  handle::Ptr{Cvoid}

  function MemoryPoolHandle(handle::Ptr{Cvoid})
    x = new(handle)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:MemoryPoolHandle_Destroy, libsealc), Clong, (Ptr{Cvoid},), x)
    end
    return x
  end
end

function alloc_byte_count(handle::MemoryPoolHandle)
  count = Ref{UInt64}(0)
  retval = ccall((:MemoryPoolHandle_AllocByteCount, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt64}),
                 handle, count)
  @check_return_value retval
  return Int(count[])
end

function memory_manager_get_pool()
  handleref = Ref{Ptr{Cvoid}}(C_NULL)
  retval = ccall((:MemoryManager_GetPool2, libsealc), Clong,
                 (Ref{Ptr{Cvoid}},),
                 handleref)
  @check_return_value retval
  return MemoryPoolHandle(handleref[])
end
