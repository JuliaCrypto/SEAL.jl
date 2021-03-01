include("utilities.jl")

using SEAL
using Printf

function example_batch_encoder()
  print_example_banner("Example: Encoders / Batch Encoder")

  parms = EncryptionParameters(SchemeType.BFV)
  poly_modulus_degree = 8192
  set_poly_modulus_degree!(parms, poly_modulus_degree)
  set_coeff_modulus!(parms, coeff_modulus_bfv_default(poly_modulus_degree))

  set_plain_modulus!(parms, plain_modulus_batching(poly_modulus_degree, 20))
  context = SEALContext(parms)
  print_parameters(context)
  println()

  context_data = first_context_data(context)
  epq = qualifiers(context_data)
  println("Batching enabled: ", using_batching(epq))

  keygen = KeyGenerator(context)
  public_key_ = PublicKey()
  create_public_key!(public_key_, keygen)
  secret_key_ = secret_key(keygen)
  relin_keys_ = RelinKeys()
  create_relin_keys!(relin_keys_, keygen)
  encryptor = Encryptor(context, public_key_)
  evaluator = Evaluator(context)
  decryptor = Decryptor(context, secret_key_)

  batch_encoder = BatchEncoder(context)
  slot_count_ = slot_count(batch_encoder)
  row_size = div(slot_count_, 2)
  println( "Plaintext matrix row size: ", row_size)

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
  println("Encode plaintext matrix:")
  encode!(plain_matrix, pod_matrix, batch_encoder)

  println("    + Decode plaintext matrix ...... Correct.")
  pod_result = similar(pod_matrix)
  decode!(pod_result, plain_matrix, batch_encoder)
  print_matrix(pod_result, row_size)

  encrypted_matrix = Ciphertext()
  print_line(@__LINE__)
  println("Encrypt plain_matrix to encrypted_matrix.")
  encrypt!(encrypted_matrix, plain_matrix, encryptor)
  println("    + Noise budget in encrypted_matrix: ",
          invariant_noise_budget(encrypted_matrix, decryptor),
          " bits")

  pod_matrix2 = ones(UInt64, slot_count_)
  pod_matrix2[2:2:slot_count_] .= 2
  plain_matrix2 = Plaintext()
  encode!(plain_matrix2, pod_matrix2, batch_encoder)
  println()
  println("Second input plaintext matrix:")
  print_matrix(pod_matrix2, row_size)

  print_line(@__LINE__)
  println("Sum, square, and relinearize.")
  add_plain_inplace!(encrypted_matrix, plain_matrix2, evaluator)
  square_inplace!(encrypted_matrix, evaluator)
  relinearize_inplace!(encrypted_matrix, relin_keys_, evaluator)
  println("    + Noise budget in result: ",
          invariant_noise_budget(encrypted_matrix, decryptor),
          " bits")

  plain_result = Plaintext()
  print_line(@__LINE__)
  println("Decrypt and decode result.")
  decrypt!(plain_result, encrypted_matrix, decryptor)
  decode!(pod_result, plain_result, batch_encoder)
  println("    + Result plaintext matrix ...... Correct.")
  print_matrix(pod_result, row_size)
end

function example_ckks_encoder()
  print_example_banner("Example: Encoders / CKKS Encoder")

  parms = EncryptionParameters(SchemeType.CKKS)

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

  encryptor = Encryptor(context, public_key_)
  evaluator = Evaluator(context)
  decryptor = Decryptor(context, secret_key_)

  encoder = CKKSEncoder(context)

  slot_count_ = slot_count(encoder)
  println("Number of slots: ", slot_count_)

  input = Float64[0.0, 1.1, 2.2, 3.3]
  println("Input vector: ")
  print_vector(input)

  plain = Plaintext()
  initial_scale = 2.0^30
  print_line(@__LINE__)
  println("Encode input vectors.")
  encode!(plain, input, initial_scale, encoder)

  output = Vector{Float64}(undef, slot_count_)
  println("    + Decode input vector ...... Correct.")
  decode!(output, plain, encoder)
  print_vector(output)

  encrypted = Ciphertext()
  print_line(@__LINE__)
  println("Encrypt input vector, square, and relinearize.")
  encrypt!(encrypted, plain, encryptor)

  square_inplace!(encrypted, evaluator)
  relinearize_inplace!(encrypted, relin_keys_, evaluator)

  println("    + Scale in squared input: ", scale(encrypted),
          " (", log2(scale(encrypted)), " bits)")

  print_line(@__LINE__)
  println("Decrypt and decode.")
  decrypt!(plain, encrypted, decryptor)
  decode!(output, plain, encoder)
  println("    + Result vector ...... Correct.")
  print_vector(output)

end

function example_encoders()
  print_example_banner("Example: Encoders")

  example_batch_encoder()
  example_ckks_encoder()
end
