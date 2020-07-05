include("utilities.jl")

using SEAL
using Printf


function bfv_performance_test(context)
  print_parameters(context)
  println()

  enc_params = parms(first_context_data(context))
  plain_modulus_ = plain_modulus(enc_params)
  poly_modulus_degree_ = poly_modulus_degree(enc_params)

  print("Generating secret/public keys: ")
  keygen = KeyGenerator(context)
  println("Done")

  secret_key_ = secret_key(keygen)
  public_key_ = public_key(keygen)

  if using_keyswitching(context)
    print("Generating relinearization keys: ")
    time_diff = @elapsedus relin_keys_ = relin_keys_local(keygen)
    println("Done [", time_diff, " microseconds]")
  end
end

function ckks_performance_test(context)
end

function example_bfv_performance_default()
  print_example_banner("BFV Performance Test with Degrees: 4096, 8192, and 16384")

  enc_parms = EncryptionParameters(SchemeType.BFV)
  poly_modulus_degree = 4096
  set_poly_modulus_degree!(enc_parms, poly_modulus_degree)
  set_coeff_modulus!(enc_parms, coeff_modulus_bfv_default(poly_modulus_degree))
  set_plain_modulus!(enc_parms, 786433)
  bfv_performance_test(SEALContext(enc_parms))

  println()
  poly_modulus_degree = 8192
  set_poly_modulus_degree!(enc_parms, poly_modulus_degree)
  set_coeff_modulus!(enc_parms, coeff_modulus_bfv_default(poly_modulus_degree))
  set_plain_modulus!(enc_parms, 786433)
  bfv_performance_test(SEALContext(enc_parms))

  println()
  poly_modulus_degree = 16384
  set_poly_modulus_degree!(enc_parms, poly_modulus_degree)
  set_coeff_modulus!(enc_parms, coeff_modulus_bfv_default(poly_modulus_degree))
  set_plain_modulus!(enc_parms, 786433)
  bfv_performance_test(SEALContext(enc_parms))

  # Comment out the following to run the biggest example
  #
  # println()
  # poly_modulus_degree = 32768
  # set_poly_modulus_degree!(enc_parms, poly_modulus_degree)
  # set_coeff_modulus!(enc_parms, coeff_modulus_bfv_default(poly_modulus_degree))
  # set_plain_modulus!(enc_parms, 786433)
  # bfv_performance_test(SEALContext(enc_parms))
end

function example_bfv_performance_custom()
end

function example_ckks_performance_default()
end

function example_ckks_performance_custom()
end

function example_performance_test()
  print_example_banner("Example: Performance Test")
end
