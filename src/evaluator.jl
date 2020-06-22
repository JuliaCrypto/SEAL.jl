
mutable struct Evaluator
  handle::Ptr{Cvoid}

  function Evaluator(context)
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
