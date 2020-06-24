
"""
    Decryptor

A `Decryptor` can be used to decrypt a `Ciphertext` instance back into a `Plaintext` instance.

See also: [`Plaintext`](@ref), [`Ciphertext`](@ref)
"""
mutable struct Decryptor <: SEALObject
  handle::Ptr{Cvoid}

  function Decryptor(context::SEALContext, secret_key::SecretKey)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:Decryptor_Create, libsealc), Clong,
                   (Ptr{Cvoid}, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                   context, secret_key, handleref)
    @check_return_value retval
    return Decryptor(handleref[])
  end

  function Decryptor(handle::Ptr{Cvoid})
    x = new(handle)
    finalizer(x) do x
      # @async println("Finalizing $x at line $(@__LINE__).")
      ccall((:Decryptor_Destroy, libsealc), Clong, (Ptr{Cvoid},), x)
    end
    return x
  end
end

function decrypt!(destination::Plaintext, encrypted::Ciphertext, decryptor::Decryptor)
  retval = ccall((:Decryptor_Decrypt, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                 decryptor, encrypted, destination)
  @check_return_value retval
  return destination
end

function invariant_noise_budget(encrypted::Ciphertext, decryptor::Decryptor)
  budgetref = Ref{Cint}(0)
  retval = ccall((:Decryptor_InvariantNoiseBudget, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{Cvoid}, Ref{Cint}),
                 decryptor, encrypted, budgetref)
  @check_return_value retval
  return Int(budgetref[])
end
