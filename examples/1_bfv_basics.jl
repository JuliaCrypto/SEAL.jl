include("utilities.jl")

using SEAL
using Printf


"""
    example_bfv_basics()

Perform some basic operations such as encryption/decryption, multiplication, addition etc. using the
BFV scheme. This routine is based on the file `native/examples/1_bfv_basics.cpp` of the original
SEAL library and should yield the exact same output.

* [SEAL](https://github.com/microsoft/SEAL)
* [native/examples/1_bfv_basics.cpp](https://github.com/microsoft/SEAL/blob/master/native/examples/1_bfv_basics.cpp)

See also: [`example_ckks_basics`](@ref)
"""
function example_bfv_basics()
  print_example_banner("Example: BFV Basics")

  parms = EncryptionParameters(SchemeType.BFV)

  poly_modulus_degree = 4096
  set_poly_modulus_degree!(parms, poly_modulus_degree)

  set_coeff_modulus!(parms, coeff_modulus_bfv_default(poly_modulus_degree))

  set_plain_modulus!(parms, 1024)

  context = SEALContext(parms)

  print_line(@__LINE__)
  println("Set encryption parameters and print")
  print_parameters(context)

  println("Parameter validation (success): ", parameter_error_message(context))

  println()
  println("~~~~~~ A naive way to calculate 4(x^2+1)(x+1)^2. ~~~~~~")

  keygen = KeyGenerator(context)
  public_key_ = public_key(keygen)
  secret_key_ = secret_key(keygen)

  encryptor = Encryptor(context, public_key_)

  evaluator = Evaluator(context)

  decryptor = Decryptor(context, secret_key_)

  print_line(@__LINE__)
  x = 6
  x_plain = Plaintext(string(x))
  println("Express x = " * string(x) * " as a plaintext polynomial 0x" * to_string(x_plain) * ".")

  print_line(@__LINE__)
  x_encrypted = Ciphertext()
  println("Encrypt x_plain to x_encrypted.")
  encrypt!(x_encrypted, x_plain, encryptor)

  println("    + size of freshly encrypted x: ", length(x_encrypted))

  println("    + noise budget in freshly encrypted x: ",
          invariant_noise_budget(x_encrypted, decryptor),
          " bits")

  x_decrypted = Plaintext()
  decrypt!(x_decrypted, x_encrypted, decryptor)
  println("    + decryption of x_encrypted: 0x", to_string(x_decrypted), " ...... Correct.")

  print_line(@__LINE__)
  println("Compute x_sq_plus_one (x^2+1).")
  x_sq_plus_one = Ciphertext()
  square!(x_sq_plus_one, x_encrypted, evaluator)
  plain_one = Plaintext("1")
  add_plain_inplace!(x_sq_plus_one, plain_one, evaluator)

  println("    + size of x_sq_plus_one: ", length(x_sq_plus_one))
  println("    + noise budget in x_sq_plus_one: ",
          invariant_noise_budget(x_sq_plus_one, decryptor),
          " bits")

  decrypted_result = Plaintext()
  decrypt!(decrypted_result, x_sq_plus_one, decryptor)
  println("    + decryption of x_sq_plus_one: 0x", to_string(decrypted_result), " ...... Correct.")

  print_line(@__LINE__)
  println("Compute x_plus_one_sq ((x+1)^2).")
  x_plus_one_sq = Ciphertext()
  add_plain!(x_plus_one_sq, x_encrypted, plain_one, evaluator)
  square_inplace!(x_plus_one_sq, evaluator)
  println("    + size of x_plus_one_sq: ", length(x_plus_one_sq))
  println("    + noise budget in x_plus_one_sq: ",
          invariant_noise_budget(x_plus_one_sq, decryptor),
          " bits")
  decrypt!(decrypted_result, x_plus_one_sq, decryptor)
  println("    + decryption of x_plus_one_sq: 0x", to_string(decrypted_result),
          " ...... Correct.")

  print_line(@__LINE__)
  println("Compute encrypted_result (4(x^2+1)(x+1)^2).")
  encrypted_result = Ciphertext()
  plain_four = Plaintext("4")
  multiply_plain_inplace!(x_sq_plus_one, plain_four, evaluator)
  multiply!(encrypted_result, x_sq_plus_one, x_plus_one_sq, evaluator)
  println("    + size of encrypted_result: ", length(encrypted_result))
  println("    + noise budget in encrypted_result: ",
          invariant_noise_budget(encrypted_result, decryptor),
          " bits")
  println("NOTE: Decryption can be incorrect if noise budget is zero.")

  println()
  println("~~~~~~ A better way to calculate 4(x^2+1)(x+1)^2. ~~~~~~")

  print_line(@__LINE__)
  println("Generate locally usable relinearization keys.")
  relin_keys_ = relin_keys_local(keygen)

  print_line(@__LINE__)
  println("Compute and relinearize x_squared (x^2),")
  println(" "^13, "then compute x_sq_plus_one (x^2+1)")
  x_squared = Ciphertext()
  square!(x_squared, x_encrypted, evaluator)
  println("    + size of x_squared: ", length(x_squared))
  relinearize_inplace!(x_squared, relin_keys_, evaluator)
  println("    + size of x_squared (after relinearization): ", length(x_squared))
  add_plain!(x_sq_plus_one, x_squared, plain_one, evaluator)
  println("    + noise budget in x_sq_plus_one: ",
          invariant_noise_budget(x_sq_plus_one, decryptor),
          " bits")
  decrypt!(decrypted_result, x_sq_plus_one, decryptor)
  println("    + decryption of x_sq_plus_one: 0x", to_string(decrypted_result), " ...... Correct.")

  print_line(@__LINE__)
  x_plus_one = Ciphertext()
  println("Compute x_plus_one (x+1),")
  println(" "^13, "then compute and relinearize x_plus_one_sq ((x+1)^2).")
  add_plain!(x_plus_one, x_encrypted, plain_one, evaluator)
  square!(x_plus_one_sq, x_plus_one, evaluator)
  println("    + size of x_plus_one_sq: ", length(x_plus_one_sq))
  relinearize_inplace!(x_plus_one_sq, relin_keys_, evaluator)
  println("    + noise budget in x_plus_one_sq: ",
          invariant_noise_budget(x_plus_one_sq, decryptor),
          " bits")
  decrypt!(decrypted_result, x_plus_one_sq, decryptor)
  println("    + decryption of x_plus_one_sq: 0x", to_string(decrypted_result),
          " ...... Correct.")

  print_line(@__LINE__)
  println("Compute and relinearize encrypted_result (4(x^2+1)(x+1)^2).")
  multiply_plain_inplace!(x_sq_plus_one, plain_four, evaluator)
  multiply!(encrypted_result, x_sq_plus_one, x_plus_one_sq, evaluator)
  println("    + size of encrypted_result: ", length(encrypted_result))
  relinearize_inplace!(encrypted_result, relin_keys_, evaluator)
  println("    + size of encrypted_result (after relinearization): ", length(encrypted_result))
  println("    + noise budget in encrypted_result: ",
          invariant_noise_budget(encrypted_result, decryptor),
          " bits")
  println()
  println("NOTE: Notice the increase in remaining noise budget.")

  print_line(@__LINE__)
  println("Decrypt encrypted_result (4(x^2+1)(x+1)^2).")
  decrypt!(decrypted_result, encrypted_result, decryptor)
  println("    + decryption of 4(x^2+1)(x+1)^2 = 0x", to_string(decrypted_result),
          " ...... Correct.")
  println()

  print_line(@__LINE__)
  println("An example of invalid parameters")
  set_poly_modulus_degree!(parms, 2048)
  context = SEALContext(parms)
  print_parameters(context)
  println("Parameter validation (failed): ", parameter_error_message(context))
  println()

  return
end
