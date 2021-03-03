
"""
    SEALContext

Heavyweight class that does validates encryption parameters of type `EncryptionParameters` and
pre-computes and stores several costly pre-computations.

See also: [`EncryptionParameters`](@ref)
"""
mutable struct SEALContext <: SEALObject
  handle::Ptr{Cvoid}

  function SEALContext(enc_param::EncryptionParameters;
                       expand_mod_chain=true, sec_level=SecLevelType.tc128)
    handleref = Ref{Ptr{Cvoid}}(C_NULL)
    retval = ccall((:SEALContext_Create, libsealc), Clong,
                   (Ptr{Cvoid}, UInt8, Cint, Ref{Ptr{Cvoid}}),
                   enc_param, expand_mod_chain, sec_level, handleref)
    @check_return_value retval
    return SEALContext(handleref[])
  end

  function SEALContext(handle::Ptr{Cvoid})
    object = new(handle)
    finalizer(destroy!, object)
    return object
  end
end

function destroy!(object::SEALContext)
  if isallocated(object)
    @check_return_value ccall((:SEALContext_Destroy, libsealc), Clong, (Ptr{Cvoid},), object)
    sethandle!(object, C_NULL)
  end

  return nothing
end

function first_parms_id(context::SEALContext)
  parms_id = zeros(UInt64, 4)
  retval = ccall((:SEALContext_FirstParmsId, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt64}),
                 context, parms_id)
  @check_return_value retval
  return parms_id
end

function last_parms_id(context::SEALContext)
  parms_id = zeros(UInt64, 4)
  retval = ccall((:SEALContext_LastParmsId, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt64}),
                 context, parms_id)
  @check_return_value retval
  return parms_id
end

function get_context_data(context::SEALContext, parms_id::DenseVector{UInt64})
  handleref = Ref{Ptr{Cvoid}}(C_NULL)
  retval = ccall((:SEALContext_GetContextData, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt64}, Ref{Ptr{Cvoid}}),
                 context, parms_id, handleref)
  @check_return_value retval
  return ContextData(handleref[], destroy_on_gc=false)
end

function key_context_data(context::SEALContext)
  handleref = Ref{Ptr{Cvoid}}(C_NULL)
  retval = ccall((:SEALContext_KeyContextData, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                 context, handleref)
  @check_return_value retval
  return ContextData(handleref[], destroy_on_gc=false)
end

function first_context_data(context::SEALContext)
  handleref = Ref{Ptr{Cvoid}}(C_NULL)
  retval = ccall((:SEALContext_FirstContextData, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                 context, handleref)
  @check_return_value retval
  return ContextData(handleref[], destroy_on_gc=false)
end

function parameter_error_message(context::SEALContext)
  len = Ref{UInt64}(0)

  # First call to obtain length (message pointer is null)
  retval = ccall((:SEALContext_ParameterErrorMessage, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt64}),
                 context, C_NULL, len)
  @check_return_value retval

  # Second call to obtain message
  message = Vector{UInt8}(undef, len[])
  retval = ccall((:SEALContext_ParameterErrorMessage, libsealc), Clong,
                 (Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt64}),
                 context, message, len)
  @check_return_value retval

  return String(message)
end

function using_keyswitching(context::SEALContext)
  valueref = Ref{UInt8}(0)
  retval = ccall((:SEALContext_UsingKeyswitching, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt8}),
                 context, valueref)
  @check_return_value retval
  return Bool(valueref[])
end


mutable struct ContextData <: SEALObject
  handle::Ptr{Cvoid}

  function ContextData(handle::Ptr{Cvoid}; destroy_on_gc=true)
    object = new(handle)
    destroy_on_gc && finalizer(destroy!, object)
    return object
  end
end

function destroy!(object::ContextData)
  if isallocated(object)
    @check_return_value ccall((:ContextData_Destroy, libsealc), Clong, (Ptr{Cvoid},), object)
    sethandle!(object, C_NULL)
  end

  return nothing
end

function chain_index(context_data::ContextData)
  index = Ref{UInt64}(0)
  retval = ccall((:ContextData_ChainIndex, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt64}),
                 context_data, index)
  @check_return_value retval
  return Int(index[])
end

function parms(context_data::ContextData)
  handleref = Ref{Ptr{Cvoid}}(C_NULL)
  retval = ccall((:ContextData_Parms, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                 context_data, handleref)
  @check_return_value retval
  return EncryptionParameters(handleref[])
end

function parms_id(context_data::ContextData)
  enc_parms = parms(context_data)
  return parms_id(enc_parms)
end

function total_coeff_modulus_bit_count(context_data::ContextData)
  bit_count = Ref{Cint}(0)
  retval = ccall((:ContextData_TotalCoeffModulusBitCount, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{Cint}),
                 context_data, bit_count)
  @check_return_value retval
  return Int(bit_count[])
end

function qualifiers(context_data::ContextData)
  handleref = Ref{Ptr{Cvoid}}(C_NULL)
  retval = ccall((:ContextData_Qualifiers, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                 context_data, handleref)
  @check_return_value retval
  return EncryptionParameterQualifiers(handleref[], destroy_on_gc=false)
end

function next_context_data(context_data::ContextData)
  handleref = Ref{Ptr{Cvoid}}(C_NULL)
  retval = ccall((:ContextData_NextContextData, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                 context_data, handleref)
  @check_return_value retval
  if handleref[] == C_NULL
    return nothing
  else
    return ContextData(handleref[], destroy_on_gc=false)
  end
end


mutable struct EncryptionParameterQualifiers <: SEALObject
  handle::Ptr{Cvoid}

  function EncryptionParameterQualifiers(handle::Ptr{Cvoid}; destroy_on_gc=true)
    object = new(handle)
    destroy_on_gc && finalizer(destroy!, object)
    return object
  end
end

function destroy!(object::EncryptionParameterQualifiers)
  if isallocated(object)
    @check_return_value ccall((:EncryptionParameterQualifiers_Destroy, libsealc), Clong, (Ptr{Cvoid},), object)
    sethandle!(object, C_NULL)
  end

  return nothing
end

function using_batching(epq::EncryptionParameterQualifiers)
  valueref = Ref{UInt8}(0)
  retval = ccall((:EPQ_UsingBatching, libsealc), Clong,
                 (Ptr{Cvoid}, Ref{UInt8}),
                 epq, valueref)
  @check_return_value retval
  return Bool(valueref[])
end
