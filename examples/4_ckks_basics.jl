include("utilities.jl")

using SEAL
using Printf


"""
    example_ckks_basics()

Perform some basic operations such as encryption/decryption, multiplication, addition etc. using the
CKKS scheme. This routine is based on the file `native/examples/4_ckks_basics.cpp` of the original
SEAL library and should yield the exact same output.

* [SEAL](https://github.com/microsoft/SEAL)
* [native/examples/4_ckks_basics.cpp](https://github.com/microsoft/SEAL/blob/master/native/examples/4_ckks_basics.cpp)

See also: [`example_ckks_basics`](@ref)
"""
function example_ckks_basics()
  print_example_banner("Example: CKKS Basics")

  parms = EncryptionParameters(SchemeType.CKKS)

  poly_modulus_degree = 8192
  set_poly_modulus_degree!(parms, poly_modulus_degree)
  set_coeff_modulus!(parms, coeff_modulus_create(poly_modulus_degree, [60, 40, 40, 60]))

  initial_scale = 2.0^40

  context = SEALContext(parms)
  print_parameters(context)
  println()

  keygen = KeyGenerator(context)
  public_key_ = PublicKey()
  create_public_key!(public_key_, keygen)
  secret_key_ = secret_key(keygen)
  relin_keys_ = relin_keys_local(keygen)
  encryptor = Encryptor(context, public_key_)
  evaluator = Evaluator(context)
  decryptor = Decryptor(context, secret_key_)

  encoder = CKKSEncoder(context)
  slot_count_ = slot_count(encoder)
  println("Number of slots: ", slot_count_)

  input = collect(range(0.0, 1.0, length=slot_count_))
  println("Input vector:")
  print_vector(input, 3, 7)

  println("Evaluating polynomial PI*x^3 + 0.4x + 1 ...")

  plain_coeff3 = Plaintext()
  plain_coeff1 = Plaintext()
  plain_coeff0 = Plaintext()
  encode!(plain_coeff3, 3.14159265, initial_scale, encoder)
  encode!(plain_coeff1, 0.4, initial_scale, encoder)
  encode!(plain_coeff0, 1.0, initial_scale, encoder)

  x_plain = Plaintext()
  print_line(@__LINE__)
  println("Encode input vectors.")
  encode!(x_plain, input, initial_scale, encoder)
  x1_encrypted = Ciphertext()
  encrypt!(x1_encrypted, x_plain, encryptor)

  x3_encrypted = Ciphertext()
  print_line(@__LINE__)
  println("Compute x^2 and relinearize:")
  square!(x3_encrypted, x1_encrypted, evaluator)
  relinearize_inplace!(x3_encrypted, relin_keys_, evaluator)
  println("    + Scale of x^2 before rescale: ", log2(scale(x3_encrypted)), " bits")

  print_line(@__LINE__)
  println("Rescale x^2.")
  rescale_to_next_inplace!(x3_encrypted, evaluator)
  println("    + Scale of x^2 after rescale: ", log2(scale(x3_encrypted)), " bits")

  print_line(@__LINE__)
  println("Compute and rescale PI*x.")
  x1_encrypted_coeff3 = Ciphertext()
  multiply_plain!(x1_encrypted_coeff3, x1_encrypted, plain_coeff3, evaluator)
  println("    + Scale of PI*x before rescale: ", log2(scale(x1_encrypted_coeff3)), " bits")
  rescale_to_next_inplace!(x1_encrypted_coeff3, evaluator)
  println("    + Scale of PI*x after rescale: ", log2(scale(x1_encrypted_coeff3)), " bits")

  print_line(@__LINE__)
  println("Compute, relinearize, and rescale (PI*x)*x^2.")
  multiply_inplace!(x3_encrypted, x1_encrypted_coeff3, evaluator)
  relinearize_inplace!(x3_encrypted, relin_keys_, evaluator)
  println("    + Scale of PI*x^3 before rescale: ", log2(scale(x3_encrypted)), " bits")
  rescale_to_next_inplace!(x3_encrypted, evaluator)
  println("    + Scale of PI*x^3 after rescale: ", log2(scale(x3_encrypted)), " bits")

  print_line(@__LINE__)
  println("Compute and rescale 0.4*x.")
  multiply_plain_inplace!(x1_encrypted, plain_coeff1, evaluator)
  println("    + Scale of 0.4*x before rescale: ", log2(scale(x1_encrypted)), " bits")
  rescale_to_next_inplace!(x1_encrypted, evaluator)
  println("    + Scale of 0.4*x after rescale: ", log2(scale(x1_encrypted)), " bits")

  println()
  print_line(@__LINE__)
  println("Parameters used by all three terms are different.")
  ci_x3 = chain_index(get_context_data(context, parms_id(x3_encrypted)))
  println("    + Modulus chain index for x3_encrypted: ", ci_x3)
  ci_x1 = chain_index(get_context_data(context, parms_id(x1_encrypted)))
  println("    + Modulus chain index for x1_encrypted: ", ci_x1)
  ci_c0 = chain_index(get_context_data(context, parms_id(plain_coeff0)))
  println("    + Modulus chain index for plain_coeff0: ", ci_c0)
  println()

  print_line(@__LINE__)
  println("The exact scales of all three terms are different:")
  @printf("    + Exact scale in PI*x^3: %.10f\n", scale(x3_encrypted))
  @printf("    + Exact scale in  0.4*x: %.10f\n", scale(x1_encrypted))
  @printf("    + Exact scale in      1: %.10f\n", scale(plain_coeff0))
  println()

  print_line(@__LINE__)
  println("Normalize scales to 2^40.")
  scale!(x3_encrypted, 2.0^40)
  scale!(x1_encrypted, 2.0^40)

  print_line(@__LINE__)
  println("Normalize encryption parameters to the lowest level.")
  last_parms_id = parms_id(x3_encrypted)
  mod_switch_to_inplace!(x1_encrypted, last_parms_id, evaluator)
  mod_switch_to_inplace!(plain_coeff0, last_parms_id, evaluator)

  print_line(@__LINE__)
  println("Compute PI*x^3 + 0.4*x + 1.")
  encrypted_result = Ciphertext()
  add!(encrypted_result, x3_encrypted, x1_encrypted, evaluator)
  add_plain_inplace!(encrypted_result, plain_coeff0, evaluator)

  plain_result = Plaintext()
  print_line(@__LINE__)
  println("Decrypt and decode PI*x^3 + 0.4x + 1.")
  println("    + Expected result:")
  true_result = similar(input)
  for (i, x) in enumerate(input)
    true_result[i] = (3.14159265 * x * x + 0.4) * x + 1
  end
  print_vector(true_result, 3, 7)

  decrypt!(plain_result, encrypted_result, decryptor)
  result = similar(input)
  decode!(result, plain_result, encoder)
  println("    + Computed result ...... Correct.")
  print_vector(result, 3, 7)

  return
end
