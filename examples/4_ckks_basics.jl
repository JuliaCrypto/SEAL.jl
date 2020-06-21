using SEAL

function example_ckks_basics()
  parms = EncryptionParameters(SchemeType.ckks)

  poly_modulus_degree = 8192

  a = coeff_modulus_create(poly_modulus_degree, [60, 40, 40, 60])

  set_coeff_modulus!(parms, a)

  b = coeff_modulus(parms)

  context = SEALContext(parms)

  keygen = KeyGenerator(context)

  pub_key = public_key(keygen)
  sec_key = secret_key(keygen)
  rel_keys = relin_keys_local(keygen)

  return
end
