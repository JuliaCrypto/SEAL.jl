using Printf

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
