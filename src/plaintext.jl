
mutable struct Plaintext
  handle::Ptr{Cvoid}
  memory_pool_handle::MemoryPoolHandle

  function Plaintext()
    memory_pool_handle = memory_manager_get_pool()
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    ccall((:Plaintext_Create1, libsealc), Clong,
          (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
          memory_pool_handle.handle, handleref)
    return Plaintext(handleref[], memory_pool_handle)
  end

  function Plaintext(handle::Ptr{Cvoid}, memory_pool_handle)
    x = new(handle, memory_pool_handle)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:Plaintext_Destroy, libsealc), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end
