include("utilities.jl")

using SEAL
using Printf


function example_rotation_ckks()
  print_example_banner("Example: Rotation / Rotation in CKKS")

  parms = EncryptionParameters(SchemeType.CKKS)

  poly_modulus_degree = 8192
  set_poly_modulus_degree!(parms, poly_modulus_degree)
  set_coeff_modulus!(parms, coeff_modulus_create(poly_modulus_degree, [40, 40, 40, 40, 40]))

  context = SEALContext(parms)
  print_parameters(context)
  println()

  keygen = KeyGenerator(context)
  public_key_ = public_key(keygen)
  secret_key_ = secret_key(keygen)
  relin_keys_ = relin_keys_local(keygen) 
  galois_keys_ = galois_keys_local(keygen)
  encryptor = Encryptor(context, public_key_)
  evaluator = Evaluator(context)
  decryptor = Decryptor(context, secret_key_)

  encoder = CKKSEncoder(context)

  slot_count_ = slot_count(encoder)
  println("Number of slots: ", slot_count_)
  input = collect(range(0.0, 1.0, length=slot_count_))
  println("Input vector:")
  print_vector(input)

  initial_scale = 2.0^50

  print_line(@__LINE__)
  println("Encode and encrypt.")
  plain = Plaintext()
  encode!(plain, input, initial_scale, encoder)
  encrypted = Ciphertext()
  encrypt!(encrypted, plain, encryptor)

  rotated = Ciphertext()
  print_line(@__LINE__)
  println("Rotate 2 steps left.")
  rotate_vector!(rotated, encrypted, 2, galois_keys_, evaluator)
  println("    + Decrypt and decode ...... Correct.")
  decrypt!(plain, rotated, decryptor)
  result = similar(input)
  decode!(result, plain, encoder)
  print_vector(result)

  return
end

function example_rotation()
  print_example_banner("Example: Rotation")

  example_rotation_ckks()
end
