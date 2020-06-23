
mutable struct Evaluator
  handle::Ptr{Cvoid}

  function Evaluator(context::SEALContext)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:Evaluator_Create, libsealc), Clong,
                   (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   context.handle, handleref)
    @check_return_value retval
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
  retval = ccall((:Evaluator_Square, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                 evaluator.handle, encrypted.handle, destination.handle, C_NULL)
  @check_return_value retval
  return destination
end

function relinearize!(destination::Ciphertext, encrypted::Ciphertext, relinkeys::RelinKeys,
                      evaluator::Evaluator)
  retval = ccall((:Evaluator_Relinearize, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                 evaluator.handle, encrypted.handle, relinkeys.handle, destination.handle, C_NULL)
  @check_return_value retval
  return destination
end

function relinearize_inplace!(encrypted::Ciphertext, relinkeys::RelinKeys, evaluator::Evaluator)
  return relinearize!(encrypted, encrypted, relinkeys, evaluator)
end

function rescale_to_next!(destination::Ciphertext, encrypted::Ciphertext, evaluator::Evaluator)
  retval = ccall((:Evaluator_RescaleToNext, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                 evaluator.handle, encrypted.handle, destination.handle, C_NULL)
  @check_return_value retval
  return destination
end

function rescale_to_next_inplace!(encrypted::Ciphertext, evaluator::Evaluator)
  return rescale_to_next!(encrypted, encrypted, evaluator)
end

function multiply_plain!(destination::Ciphertext, encrypted::Ciphertext, plain::Plaintext,
                         evaluator::Evaluator)
  retval = ccall((:Evaluator_MultiplyPlain, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                 evaluator.handle, encrypted.handle, plain.handle, destination.handle, C_NULL)
  @check_return_value retval
  return destination
end

function multiply_plain_inplace!(encrypted::Ciphertext, plain::Plaintext,
                                  evaluator::Evaluator)
  return multiply_plain!(encrypted, encrypted, plain, evaluator)
end

function multiply!(destination::Ciphertext, encrypted1::Ciphertext, encrypted2::Ciphertext,
                   evaluator::Evaluator)
  retval = ccall((:Evaluator_Multiply, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                 evaluator.handle, encrypted1.handle, encrypted1.handle, destination.handle, C_NULL)
  @check_return_value retval
  return destination
end

function multiply_inplace!(encrypted1::Ciphertext, encrypted2::Ciphertext, evaluator::Evaluator)
  return multiply!(encrypted1, encrypted1, encrypted2, evaluator)
end

function mod_switch_to!(destination::Ciphertext, encrypted::Ciphertext, parms_id,
                        evaluator::Evaluator)
  retval = ccall((:Evaluator_ModSwitchTo1, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ref{UInt64}, Ptr{Cvoid}, Ptr{Cvoid}),
                 evaluator.handle, encrypted.handle, parms_id, destination.handle, C_NULL)
  @check_return_value retval
  return destination
end

function mod_switch_to_inplace!(encrypted::Ciphertext, parms_id, evaluator::Evaluator)
  return mod_switch_to!(encrypted, encrypted, parms_id, evaluator)
end

function mod_switch_to!(destination::Plaintext, plain::Plaintext, parms_id, evaluator::Evaluator)
  retval = ccall((:Evaluator_ModSwitchTo2, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ref{UInt64}, Ptr{Cvoid}),
                 evaluator.handle, plain.handle, parms_id, destination.handle)
  @check_return_value retval
  return destination
end

function mod_switch_to_inplace!(plain::Plaintext, parms_id, evaluator::Evaluator)
  return mod_switch_to!(plain, plain, parms_id, evaluator)
end
