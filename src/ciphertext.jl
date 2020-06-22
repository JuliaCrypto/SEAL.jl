
mutable struct Ciphertext
  handle::Ptr{Cvoid}
  memory_pool_handle::MemoryPoolHandle

  function Ciphertext()
    memory_pool_handle = memory_manager_get_pool()
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    ccall((:Ciphertext_Create1, seal_library_path), Clong,
          (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
          memory_pool_handle.handle, handleref)
    return Ciphertext(handleref[], memory_pool_handle)
  end

  function Ciphertext(handle::Ptr{Cvoid}, memory_pool_handle)
    x = new(handle, memory_pool_handle)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:Ciphertext_Destroy, seal_library_path), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end
