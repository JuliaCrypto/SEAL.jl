using SEAL
using Printf

include("utilities.jl")

function example_ckks_basics()
  parms = EncryptionParameters(SchemeType.ckks)

  poly_modulus_degree = 8192
  set_poly_modulus_degree!(parms, poly_modulus_degree)
  set_coeff_modulus!(parms, coeff_modulus_create(poly_modulus_degree, [60, 40, 40, 60]))

  initial_scale = 2.0^40

  context = SEALContext(parms)

  keygen = KeyGenerator(context)
  public_key_ = public_key(keygen)
  secret_key_ = secret_key(keygen)
  relin_keys_ = relin_keys_local(keygen)
  encryptor = Encryptor(context, public_key_)
  evaluator = Evaluator(context)
  decryptor = Decryptor(context, secret_key_)

  encoder = CKKSEncoder(context)
  slot_count_ = slot_count(encoder)
  println("Number of slots: ", slot_count_)

  input = collect(range(0.0, 1.0, length=slot_count_))
  println()
  println("Input vector:")
  print("  ")
  show(IOContext(stdout, :limit => true, :displaysize => (6, 1)), input)
  println()
  println()

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
    #=cout << "    + Modulus chain index for x3_encrypted: "=#
    #=     << context->get_context_data(x3_encrypted.parms_id())->chain_index() << endl;=#
    #=cout << "    + Modulus chain index for x1_encrypted: "=#
    #=     << context->get_context_data(x1_encrypted.parms_id())->chain_index() << endl;=#
    #=cout << "    + Modulus chain index for plain_coeff0: "=#
    #=     << context->get_context_data(plain_coeff0.parms_id())->chain_index() << endl;=#
    #=cout << endl;=#

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

  return
end
