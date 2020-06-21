using SEAL

function example_ckks_basics()
  parms = EncryptionParameters(SchemeType.ckks)

  poly_modulus_degree = 8192
  set_poly_modulus_degree!(parms, poly_modulus_degree)
  set_coeff_modulus!(parms, coeff_modulus_create(poly_modulus_degree, [60, 40, 40, 60]))

  scale = 2.0^40

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
  println("Input vector:")
  show(IOContext(stdout, :limit => true, :displaysize => (6, 1)), input)
  println()

  println("Evaluating polynomial PI*x^3 + 0.4x + 1 ...")

  return
end
