include("utilities.jl")

using SEAL
using Printf


function example_levels()
  print_example_banner("Example: Levels")

  enc_parms = EncryptionParameters(SchemeType.BFV)

  poly_modulus_degree = 8192
  set_poly_modulus_degree!(enc_parms, poly_modulus_degree)

  set_coeff_modulus!(enc_parms, coeff_modulus_create(poly_modulus_degree, [50, 30, 30, 50, 50]))

  set_plain_modulus!(enc_parms, plain_modulus_batching(poly_modulus_degree, 20))

  context = SEALContext(enc_parms)
  print_parameters(context)
  println()

  print_line(@__LINE__)
  println("Print the modulus switching chain.")

  context_data = key_context_data(context)
  println("----> Level (chain index): ", chain_index(context_data))
  println(" ...... key_context_data()")
  print("      parms_id:")
  for parm_id in parms_id(context_data)
    @printf(" %016x", parm_id)
  end
  println()
  print("      coeff_modulus primes: ")
  for prime in coeff_modulus(parms(context_data))
    @printf("%016x ", value(prime))
  end
  println()
  println("\\")
  print(" \\-->")

  context_data = first_context_data(context)
  while !isnothing(context_data)
    print(" Level (chain index): ", chain_index(context_data))
    if parms_id(context_data) == first_parms_id(context)
      println(" ...... first_context_data()")
    elseif parms_id(context_data) == last_parms_id(context)
      println(" ...... last_context_data()")
    else
      println()
    end
    print("      parms_id:")
    for parm_id in parms_id(context_data)
      @printf(" %016x", parm_id)
    end
    println()
    print("      coeff_modulus primes: ")
    for prime in coeff_modulus(parms(context_data))
      @printf("%016x ", value(prime))
    end
    println()
    println("\\")
    print(" \\-->")

    context_data = next_context_data(context_data)
  end
  println(" End of chain reached")

  keygen = KeyGenerator(context)
  public_key_ = public_key(keygen)
  secret_key_ = secret_key(keygen)
  relin_keys_ = relin_keys_local(keygen)

  galois_keys_ = galois_keys_local(keygen)
  print_line(@__LINE__)
  println("Print the parameter IDs of generated elements.")
  print("    + public_key:  ")
  for parm_id in parms_id(public_key_)
    @printf(" %016x", parm_id)
  end
  println()
  print("    + secret_key:  ")
  for parm_id in parms_id(secret_key_)
    @printf(" %016x", parm_id)
  end
  println()
  print("    + relin_keys:  ")
  for parm_id in parms_id(relin_keys_)
    @printf(" %016x", parm_id)
  end
  println()
  print("    + galois_keys: ")
  for parm_id in parms_id(galois_keys_)
    @printf(" %016x", parm_id)
  end
  println()

  encryptor = Encryptor(context, public_key_)
  evaluator = Evaluator(context)
  decryptor = Decryptor(context, secret_key_)

  plain = Plaintext("1x^3 + 2x^2 + 3x^1 + 4")
  encrypted = Ciphertext()
  encrypt!(encrypted, plain, encryptor)
  print("    + plain:       ")
  for parm_id in parms_id(plain)
    @printf(" %016x", parm_id)
  end
  println(" (not set in BFV)")
  print("    + encrypted:   ")
  for parm_id in parms_id(encrypted)
    @printf(" %016x", parm_id)
  end
  println()
  println()

  print_line(@__LINE__)
  println("Perform modulus switching on encrypted and print.")
  context_data = first_context_data(context)
  print("---->")
  while !isnothing(next_context_data(context_data))
    println(" Level (chain index): ", chain_index(context_data))
    print("      parms_id of encrypted: ")
    for parm_id in parms_id(encrypted)
      @printf(" %016x", parm_id)
    end
    println()
    println("      Noise budget at this level: ", invariant_noise_budget(encrypted, decryptor),
            " bits")
    println("\\")
    print(" \\-->")
    mod_switch_to_next_inplace!(encrypted, evaluator)
    context_data = next_context_data(context_data)
  end
  println(" Level (chain index): ", chain_index(context_data))
  print("      parms_id of encrypted: ")
  for parm_id in parms_id(encrypted)
    @printf(" %016x", parm_id)
  end
  println()
  println("      Noise budget at this level: ", invariant_noise_budget(encrypted, decryptor),
          " bits")
  println("\\")
  print(" \\-->")
  println(" End of chain reached")
  println()

  print_line(@__LINE__)
  println("Decrypt still works after modulus switching.")
  decrypt!(plain, encrypted, decryptor)
  print("    + Decryption of encrypted: ", to_string(plain))
  println(" ...... Correct.")
  println()

  println("Computation is more efficient with modulus switching.")
  print_line(@__LINE__)
  println("Compute the 8th power.")
  encrypt!(encrypted, plain, encryptor)
  println("    + Noise budget fresh:                   ",
          invariant_noise_budget(encrypted, decryptor),
          " bits")
  square_inplace!(encrypted, evaluator)
  relinearize_inplace!(encrypted, relin_keys_, evaluator)
  println("    + Noise budget of the 2nd power:         ",
          invariant_noise_budget(encrypted, decryptor),
          " bits")
  square_inplace!(encrypted, evaluator)
  relinearize_inplace!(encrypted, relin_keys_, evaluator)
  println("    + Noise budget of the 4th power:         ",
          invariant_noise_budget(encrypted, decryptor),
          " bits")

  mod_switch_to_next_inplace!(encrypted, evaluator)
  println("    + Noise budget after modulus switching:  ",
          invariant_noise_budget(encrypted, decryptor),
          " bits")

  square_inplace!(encrypted, evaluator)
  relinearize_inplace!(encrypted, relin_keys_, evaluator)
  println("    + Noise budget of the 8th power:         ",
          invariant_noise_budget(encrypted, decryptor),
          " bits")
  mod_switch_to_next_inplace!(encrypted, evaluator)
  println("    + Noise budget after modulus switching:  ",
          invariant_noise_budget(encrypted, decryptor),
          " bits")

  decrypt!(plain, encrypted, decryptor)
  println("    + Decryption of the 8th power (hexadecimal) ...... Correct.")
  println("    ", to_string(plain))
  println()

  context = SEALContext(enc_parms, expand_mod_chain=false)

  println("Optionally disable modulus switching chain expansion.")
  print_line(@__LINE__)
  println("Print the modulus switching chain.")
  print("---->")
  context_data = key_context_data(context)
  while !isnothing(context_data)
    println(" Level (chain index): ", chain_index(context_data))
    print("      parms_id:")
    for parm_id in parms_id(context_data)
      @printf(" %016x", parm_id)
    end
    println()
    print("      coeff_modulus primes: ")
    for prime in coeff_modulus(parms(context_data))
      @printf("%016x ", value(prime))
    end
    println()
    println("\\")
    print(" \\-->")

    context_data = next_context_data(context_data)
  end
  println(" End of chain reached")

end
