
mutable struct Evaluator
  handle::Ptr{Cvoid}

  function Evaluator(context::SEALContext)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    ccall((:Evaluator_Create, libsealc), Clong,
          (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
          context.handle, handleref)
    return Evaluator(handleref[])
  end

  function Evaluator(handle::Ptr{Cvoid})
    x = new(handle)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:Evaluator_Destroy, libsealc), Clong,
            (Ptr{Cvoid},),
            x.handle)
    end
    return x
  end
end

function square!(destination::Ciphertext, encrypted::Ciphertext, evaluator::Evaluator)
  ccall((:Evaluator_Square, libsealc), Clong,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
        evaluator.handle, encrypted.handle, destination.handle, C_NULL)
  return destination
end

function relinearize!(destination::Ciphertext, encrypted::Ciphertext, relinkeys::RelinKeys,
                      evaluator::Evaluator)
  ccall((:Evaluator_Relinearize, libsealc), Clong,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
        evaluator.handle, encrypted.handle, relinkeys.handle, destination.handle, C_NULL)
  return destination
end

function relinearize_inplace!(encrypted::Ciphertext, relinkeys::RelinKeys, evaluator::Evaluator)
  return relinearize!(encrypted, encrypted, relinkeys, evaluator)
end

function rescale_to_next!(destination::Ciphertext, encrypted::Ciphertext, evaluator::Evaluator)
  ccall((:Evaluator_RescaleToNext, libsealc), Clong,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
        evaluator.handle, encrypted.handle, destination.handle, C_NULL)
  return destination
end

function rescale_to_next_inplace!(encrypted::Ciphertext, evaluator::Evaluator)
  return rescale_to_next!(encrypted, encrypted, evaluator)
end
