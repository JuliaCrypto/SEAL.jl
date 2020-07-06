using SEAL

include("1_bfv_basics.jl")
include("2_encoders.jl")
include("3_levels.jl")
include("4_ckks_basics.jl")
include("5_rotation.jl")
include("6_serialization.jl")
include("7_performance.jl")

function seal_examples()
  println("Microsoft SEAL version: ", version())
  while true
    println("+---------------------------------------------------------+")
    println("| The following examples should be executed while reading |")
    println("| comments in associated files in native/examples/.       |")
    println("+---------------------------------------------------------+")
    println("| Examples                   | Source Files               |")
    println("+----------------------------+----------------------------+")
    println("| 1. BFV Basics              | 1_bfv_basics.cpp           |")
    println("| 2. Encoders                | 2_encoders.cpp             |")
    println("| 3. Levels                  | 3_levels.cpp               |")
    println("| 4. CKKS Basics             | 4_ckks_basics.cpp          |")
    println("| 5. Rotation                | 5_rotation.cpp             |")
    println("| 6. Serialization           | 6_serialization.cpp        |")
    println("| 7. Performance Test        | 7_performance.cpp          |")
    println("+----------------------------+----------------------------+")

    selection = 0
    invalid = true
    while true
      println()
      print("> Run example (1 ~ 7) or exit (0): ")
      input = readline()
      if !isopen(stdin)
        return
      end
      try
        selection = parse(Int, input)
        break
      catch
        println("  [Beep~~] Invalid option: type 0 ~ 7")
        continue
      end
    end

    if selection == 1
      example_bfv_basics()
    elseif selection == 2
      example_encoders()
    elseif selection == 3
      example_levels()
    elseif selection == 4
      example_ckks_basics()
    elseif selection == 5
      example_rotation()
    elseif selection == 6
      example_serialization()
    elseif selection == 7
      example_performance_test()
    elseif selection == 0
      return
    end
  end

  return
end
