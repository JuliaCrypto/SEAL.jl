using SEAL

function example_ckks_basics()
  parms = EncryptionParameters(SchemeType.ckks)

  poly_modulus_degree = 8192

  a = coeff_modulus_create(poly_modulus_degree, [60, 40, 40, 60])

  set_coeff_modulus!(parms, a)

  b = coeff_modulus(parms)

  context = SEALContext(parms)

  keygen = KeyGenerator(context)

  public_key_ = public_key(keygen)
  secret_key_ = secret_key(keygen)
  relin_keys_ = relin_keys_local(keygen)

  encryptor = Encryptor(context, public_key_)

  return
end
