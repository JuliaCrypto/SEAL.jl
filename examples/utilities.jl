
function print_line(line_number)
  if line_number < 10
    padding = "  "
  elseif line_number < 100
    padding = " "
  end
  print("Line ", padding, line_number, " --> ")
end
