include("utilities.jl")

using SEAL
using Printf


function example_integer_encoder()
  print_example_banner("Example: Encoders / Integer Encoder")

  parms = EncryptionParameters(SchemeType.BFV)
  poly_modulus_degree = 4096
  set_poly_modulus_degree!(parms, poly_modulus_degree)
  set_coeff_modulus!(parms, coeff_modulus_bfv_default(poly_modulus_degree))

  set_plain_modulus!(parms, 512)
  context = SEALContext(parms)
  print_parameters(context)
  println()

  keygen = KeyGenerator(context)
  public_key_ = public_key(keygen)
  secret_key_ = secret_key(keygen)
  encryptor = Encryptor(context, public_key_)
  evaluator = Evaluator(context)
  decryptor = Decryptor(context, secret_key_)

  encoder = IntegerEncoder(context)

  value1 = Int32(5)
  plain1 = encode(value1, encoder)
  print_line(@__LINE__)
  println("Encode ", value1, " as polynomial ", to_string(plain1), " (plain1),")

  value2 = Int32(-7)
  plain2 = encode(value2, encoder)
  println(" "^13, "encode ", value2, " as polynomial ", to_string(plain2), " (plain2).")

  print_line(@__LINE__)
  encrypted1 = Ciphertext()
  encrypted2 = Ciphertext()
  println("Encrypt plain1 to encrypted1 and plain2 to encrypted2.")
  encrypt!(encrypted1, plain1, encryptor)
  encrypt!(encrypted2, plain2, encryptor)
  println("    + Noise budget in encrypted1: ", invariant_noise_budget(encrypted1, decryptor),
          " bits")
  println("    + Noise budget in encrypted2: ", invariant_noise_budget(encrypted2, decryptor),
          " bits")

  encrypt!(encrypted2, plain2, encryptor)
  encrypted_result = Ciphertext()
  print_line(@__LINE__)
  println("Compute encrypted_result = (-encrypted1 + encrypted2) * encrypted2.")
  negate!(encrypted_result, encrypted1, evaluator)
  add_inplace!(encrypted_result, encrypted2, evaluator)
  multiply_inplace!(encrypted_result, encrypted2, evaluator)
  println("    + Noise budget in encrypted_result: ",
          invariant_noise_budget(encrypted_result, decryptor),
          " bits")

  plain_result = Plaintext()
  print_line(@__LINE__)
  println("Decrypt encrypted_result to plain_result.")
  decrypt!(plain_result, encrypted_result, decryptor)

  println("    + Plaintext polynomial: ", to_string(plain_result))

  print_line(@__LINE__)
  println("Decode plain_result.")
  println("    + Decoded integer: ", decode_int32(plain_result, encoder), "...... Correct.")

  return
end

function example_encoders()
  print_example_banner("Example: Encoders")

  example_integer_encoder()
  # example_batch_encoder()
  # example_ckks_encoder()
end
