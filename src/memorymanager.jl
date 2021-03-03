
mutable struct MemoryPoolHandle <: SEALObject
  handle::Ptr{Cvoid}

  function MemoryPoolHandle(handle::Ptr{Cvoid})
    object = new(handle)
    finalizer(destroy!, object)
    return object
  end
end

function destroy!(object::MemoryPoolHandle)
  if isallocated(object)
    @check_return_value ccall((:MemoryPoolHandle_Destroy, libsealc), Clong, (Ptr{Cvoid},), object)
    sethandle!(object, C_NULL)
  end

  return nothing
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
