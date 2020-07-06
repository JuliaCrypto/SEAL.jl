using SEAL
using Printf

function print_example_banner(title)
  if isempty(title)
    return nothing
  end

  title_length = length(title)
  banner_length = title_length + 2 * 10
  banner_border = "+" * "-"^(banner_length - 2) * "+"
  banner_center = "|" * " "^9 * title * " "^9 * "|"

  println()
  println(banner_border)
  println(banner_center)
  println(banner_border)
end

function print_parameters(context::SEALContext)
  context_data = key_context_data(context)
  encryption_parms = parms(context_data)
  scheme_type = scheme(encryption_parms)
  if scheme_type == SchemeType.BFV
    scheme_name = "BFV"
  elseif scheme_type == SchemeType.CKKS
    scheme_name = "CKKS"
  else
    error("unsupported scheme")
  end

  println("/")
  println("| Encryption parameters :")
  println("|   scheme: ", scheme_name)
  println("|   poly_modulus_degree: ", poly_modulus_degree(encryption_parms))

  print("|   coeff_modulus size: ", total_coeff_modulus_bit_count(context_data), " (")
  bit_counts = [bit_count(modulus) for modulus in coeff_modulus(encryption_parms)]
  print(join(bit_counts, " + "))
  println(") bits")

  if scheme_type == SchemeType.BFV
    println("|   plain_modulus: ", value(plain_modulus(encryption_parms)))
  end

  println("\\")
end

function print_line(line_number)
  if line_number < 10
    padding = "  "
  elseif line_number < 100
    padding = " "
  else
    padding = ""
  end
  print("Line ", padding, line_number, " --> ")
end

function print_vector(vector, print_size=4, prec=3)
  slot_count = length(vector)
  println()
  if slot_count <= 2 * print_size
    print("    [ ")
    if prec == 7
      @printf "%.7f" first(vector)
    else
      @printf "%.3f" first(vector)
    end
    for i in 2:slot_count
      if prec == 7
        @printf ", %.7f" vector[i]
      else
        @printf ", %.3f" vector[i]
      end
    end
    println(" ]")
  else
    print("    [ ")
    if prec == 7
      @printf "%.7f" first(vector)
    else
      @printf "%.3f" first(vector)
    end
    for i in 2:print_size
      if prec == 7
        @printf ", %.7f" vector[i]
      else
        @printf ", %.3f" vector[i]
      end
    end
    if slot_count > 2 * print_size
      print(", ...")
    end
    for i in (slot_count - print_size + 1):slot_count
      if prec == 7
        @printf ", %.7f" vector[i]
      else
        @printf ", %.3f" vector[i]
      end
    end
    println(" ]")
  end
  println()
end

function print_matrix(matrix, row_size)
  print_size = 5

  println()

  # First row
  print("    [")
  for i in 1:print_size
    @printf("%3d,", matrix[i])
  end
  print(" ...,")
  for i in (row_size - print_size + 1):row_size
    if i != row_size
      @printf("%3d,", matrix[i])
    else
      @printf("%3d ]\n", matrix[i])
    end
  end

  # Second row
  print("    [")
  for i in (row_size + 1):(row_size + print_size)
    @printf("%3d,", matrix[i])
  end
  print(" ...,")
  for i in (2 * row_size - print_size + 1):(2 * row_size)
    if i != 2 * row_size
      @printf("%3d,", matrix[i])
    else
      @printf("%3d ]\n", matrix[i])
    end
  end

  println()
end


"""
    @elapsedus(ex)

Return integer number of elapsed microseconds required for executing `ex`. Modified from
`Base.@elapsed`, which returns the number of seconds as a floating point number.

See also: [`@elapsed`](@ref)
"""
macro elapsedus(ex)
  quote
    while false; end # compiler heuristic: compile this block (alter this if the heuristic changes)
    local t0 = time_ns()
    $(esc(ex))
    Int(div(time_ns() - t0, 1000))
  end
end
