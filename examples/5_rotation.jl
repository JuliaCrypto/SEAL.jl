include("utilities.jl")

using SEAL
using Printf


"""
    example_rotation_bfv()

Perform some rotation on data encryped with the BFV scheme. This routine is based on the file
`native/examples/5_rotation.cpp` of the original SEAL library and should yield the exact same
output.

* [SEAL](https://github.com/microsoft/SEAL)
* [native/examples/5_rotation.cpp](https://github.com/microsoft/SEAL/blob/master/native/examples/5_rotation.cpp)
"""
function example_rotation_bfv()
  print_example_banner("Example: Rotation / Rotation in BFV")

  parms = EncryptionParameters(SchemeType.bfv)

  poly_modulus_degree = 8192
  set_poly_modulus_degree!(parms, poly_modulus_degree)

  set_coeff_modulus!(parms, coeff_modulus_bfv_default(poly_modulus_degree))
  set_plain_modulus!(parms, plain_modulus_batching(poly_modulus_degree, 20))

  context = SEALContext(parms)
  print_parameters(context)
  println()

  keygen = KeyGenerator(context)
  secret_key_ = secret_key(keygen)
  public_key_ = PublicKey()
  create_public_key!(public_key_, keygen)
  relin_keys_ = RelinKeys()
  create_relin_keys!(relin_keys_, keygen)
  encryptor = Encryptor(context, public_key_)
  evaluator = Evaluator(context)
  decryptor = Decryptor(context, secret_key_)

  batch_encoder = BatchEncoder(context)
  slot_count_ = slot_count(batch_encoder)
  row_size = div(slot_count_, 2)
  println("Plaintext matrix row size: ", row_size)

  pod_matrix = zeros(UInt64, slot_count_)
  pod_matrix[1] = 0
  pod_matrix[2] = 1
  pod_matrix[3] = 2
  pod_matrix[4] = 3
  pod_matrix[row_size + 1] = 4
  pod_matrix[row_size + 2] = 5
  pod_matrix[row_size + 3] = 6
  pod_matrix[row_size + 4] = 7

  println("Input plaintext matrix:")
  print_matrix(pod_matrix, row_size)

  plain_matrix = Plaintext()
  print_line(@__LINE__)
  println("Encode and encrypt.")
  encode!(plain_matrix, pod_matrix, batch_encoder)
  encrypted_matrix = Ciphertext()
  encrypt!(encrypted_matrix, plain_matrix, encryptor)
  println("    + Noise budget in fresh encryption: ",
          invariant_noise_budget(encrypted_matrix, decryptor),
          " bits")
  println()

  galois_keys = GaloisKeys()
  create_galois_keys!(galois_keys, keygen)

  print_line(@__LINE__)
  println("Rotate rows 3 steps left.")
  rotate_rows_inplace!(encrypted_matrix, 3, galois_keys, evaluator)
  plain_result = Plaintext()
  println("    + Noise budget after rotation: ",
          invariant_noise_budget(encrypted_matrix, decryptor),
          " bits")
  println("    + Decrypt and decode ...... Correct.")
  decrypt!(plain_result, encrypted_matrix, decryptor)
  decode!(pod_matrix, plain_result, batch_encoder)
  print_matrix(pod_matrix, row_size)

  print_line(@__LINE__)
  println("Rotate columns.")
  rotate_columns_inplace!(encrypted_matrix, galois_keys, evaluator)
  println("    + Noise budget after rotation: ",
          invariant_noise_budget(encrypted_matrix, decryptor),
          " bits")
  println("    + Decrypt and decode ...... Correct.")
  decrypt!(plain_result, encrypted_matrix, decryptor)
  decode!(pod_matrix, plain_result, batch_encoder)
  print_matrix(pod_matrix, row_size)

  print_line(@__LINE__)
  println("Rotate rows 4 steps right.")
  rotate_rows_inplace!(encrypted_matrix, -4, galois_keys, evaluator)
  plain_result = Plaintext()
  println("    + Noise budget after rotation: ",
          invariant_noise_budget(encrypted_matrix, decryptor),
          " bits")
  println("    + Decrypt and decode ...... Correct.")
  decrypt!(plain_result, encrypted_matrix, decryptor)
  decode!(pod_matrix, plain_result, batch_encoder)
  print_matrix(pod_matrix, row_size)
end


"""
    example_rotation_ckks()

Perform some rotation on data encryped with the CKKS scheme. This routine is based on the file
`native/examples/5_rotation.cpp` of the original SEAL library and should yield the exact same
output.

* [SEAL](https://github.com/microsoft/SEAL)
* [native/examples/5_rotation.cpp](https://github.com/microsoft/SEAL/blob/master/native/examples/5_rotation.cpp)
"""
function example_rotation_ckks()
  print_example_banner("Example: Rotation / Rotation in CKKS")

  parms = EncryptionParameters(SchemeType.ckks)

  poly_modulus_degree = 8192
  set_poly_modulus_degree!(parms, poly_modulus_degree)
  set_coeff_modulus!(parms, coeff_modulus_create(poly_modulus_degree, [40, 40, 40, 40, 40]))

  context = SEALContext(parms)
  print_parameters(context)
  println()

  keygen = KeyGenerator(context)
  public_key_ = PublicKey()
  create_public_key!(public_key_, keygen)
  secret_key_ = secret_key(keygen)
  relin_keys_ = RelinKeys()
  create_relin_keys!(relin_keys_, keygen) 
  galois_keys_ = GaloisKeys()
  create_galois_keys!(galois_keys_, keygen)
  encryptor = Encryptor(context, public_key_)
  evaluator = Evaluator(context)
  decryptor = Decryptor(context, secret_key_)

  encoder = CKKSEncoder(context)

  slot_count_ = slot_count(encoder)
  println("Number of slots: ", slot_count_)
  input = collect(range(0.0, 1.0, length=slot_count_))
  println("Input vector:")
  print_vector(input, 3, 7)

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
  print_vector(result, 3, 7)

  return
end

function example_rotation()
  print_example_banner("Example: Rotation")

  example_rotation_bfv()
  example_rotation_ckks()
end
