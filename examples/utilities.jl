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
  println("|   poly_modulus_degree: ", get_poly_modulus_degree(encryption_parms))

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

function print_vector(vector, print_size=3)
  slot_count = length(vector)
  println()
  if slot_count <= 2 * print_size
    print("    [ ")
    @printf "%.7f" first(vector)
    for i in 2:slot_count
      @printf ", %.7f" vector[i]
    end
    println(" ]")
  else
    print("    [ ")
    @printf "%.7f" first(vector)
    for i in 2:print_size
      @printf ", %.7f" vector[i]
    end
    if slot_count > 2 * print_size
      print(", ...")
    end
    for i in (slot_count - print_size + 1):slot_count
      @printf ", %.7f" vector[i]
    end
    println(" ]")
  end
  println()
end
