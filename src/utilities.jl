
function check_return_value(value)
  if value == 0
    return true
  elseif value == 0x80004003
    error("invalid pointer/null pointer error in SEAL function (E_POINTER)")
  elseif value == 0x80070057
    error("invalid argument error (E_INVALIDARG)")
  elseif value == 0x8007000E
    error("out of memory error in SEAL function (E_OUTOFMEMORY)")
  elseif value == 0x8000FFFF
    error("unexpected error in SEAL function (E_UNEXPECTED)")
  elseif value == 0x80131620
    error("I/O error in SEAL function (COR_E_IO)")
  elseif value == 0x80131509
    error("invalid operation error in SEAL function (COR_E_INVALIDOPERATION)")
  end
end
