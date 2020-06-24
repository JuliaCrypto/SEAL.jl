
"""
    check_return_value(value, location="")

Check the return value `value` of calls to C bindings of the SEAL library and throw an exception if
there were errors. `location` can be used to pass information about were the error occurred and will
be printed as well.

See also: [`@check_return_value`](@ref)
"""
function check_return_value(value, location="")
  if isempty(location)
    loc = ""
  else
    loc = " at $location"
  end

  if value == 0
    return true
  elseif value == 0x80004003
    error("invalid pointer/null pointer error in SEAL function (E_POINTER)", loc)
  elseif value == 0x80070057
    error("invalid argument error (E_INVALIDARG)", loc)
  elseif value == 0x8007000E
    error("out of memory error in SEAL function (E_OUTOFMEMORY)", loc)
  elseif value == 0x8000FFFF
    error("unexpected error in SEAL function (E_UNEXPECTED)", loc)
  elseif value == 0x80131620
    error("I/O error in SEAL function (COR_E_IO)", loc)
  elseif value == 0x80131509
    error("invalid operation error in SEAL function (COR_E_INVALIDOPERATION)", loc)
  else
    error("unknown error", loc)
  end
end

"""
    @check_return_value value

Call `check_return_value(value, location)` with `location` being a string of the format
`<filename>:<line_number>`.

See also: [`check_return_value`](@ref)
"""
macro check_return_value(value)
  return quote
    check_return_value($(esc(value)),
                       join([$(string(__source__.file)), $(string(__source__.line))], ":"))
  end
end
