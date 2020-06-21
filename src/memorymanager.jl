
mutable struct MemoryPoolHandle
  handle::Ptr{Cvoid}

  function MemoryPoolHandle(handle::Ptr{Cvoid})
    x = new(handle)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:MemoryPoolHandle_Destroy, seal_library_path), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end

function memory_manager_get_pool()
  poolhandleref = Ref{Ptr{Cvoid}}(C_NULL)
  ccall((:MemoryManager_GetPool2, seal_library_path), Clong,
        (Ref{Ptr{Cvoid}},),
        poolhandleref)
  return MemoryPoolHandle(poolhandleref[])
end
