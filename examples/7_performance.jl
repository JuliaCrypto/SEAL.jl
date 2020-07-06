include("utilities.jl")

using SEAL
using Printf
using Random


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

    if !using_batching(qualifiers(key_context_data(context)))
      return
    end

    print("Generating Galois keys: ")
    time_diff = @elapsedus galois_keys_ = galois_keys_local(keygen)
    println("Done [", time_diff, " microseconds]")
  end

  encryptor = Encryptor(context, public_key_)
  decryptor = Decryptor(context, secret_key_)
  evaluator = Evaluator(context)
  batch_encoder = BatchEncoder(context)
  encoder = IntegerEncoder(context)

  time_batch_sum = 0
  time_unbatch_sum = 0
  time_encrypt_sum = 0
  time_decrypt_sum = 0
  time_add_sum = 0
  time_multiply_sum = 0
  time_multiply_plain_sum = 0
  time_square_sum = 0
  time_relinearize_sum = 0
  time_rotate_rows_one_step_sum = 0
  time_rotate_rows_random_sum = 0
  time_rotate_columns_sum = 0

  count = 10

  slot_count_ = slot_count(batch_encoder)
  pod_vector = rand(RandomDevice(), UInt64, slot_count_) .% value(plain_modulus_)

  print("Running tests ")
  for i in 1:count
    plain = Plaintext(poly_modulus_degree(enc_params), 0)
    time_batch_sum += @elapsedus encode!(plain, pod_vector, batch_encoder)

    pod_vector2 = Vector{UInt64}(undef, slot_count_)
    time_unbatch_sum += @elapsedus decode!(pod_vector2, plain, batch_encoder)

    if pod_vector2 != pod_vector
      error("Batch/unbatch failed. Something is wrong.")
    end

    encrypted = Ciphertext(context)
    time_encrypt_sum += @elapsedus encrypt!(encrypted, plain, encryptor)

    plain2 = Plaintext(poly_modulus_degree(enc_params), 0)
    time_decrypt_sum += @elapsedus decrypt!(plain2, encrypted, decryptor)

    if plain2 != plain
      error("Encrypt/decrypt failed. Something is wrong.")
    end

    encrypted1 = Ciphertext(context)
    encrypt!(encrypted1, encode(UInt64(i), encoder), encryptor)
    encrypted2 = Ciphertext(context)
    encrypt!(encrypted2, encode(UInt64(i + 1), encoder), encryptor)
    time_add_sum += @elapsedus begin
      add_inplace!(encrypted1, encrypted1, evaluator)
      add_inplace!(encrypted2, encrypted2, evaluator)
      add_inplace!(encrypted1, encrypted2, evaluator)
    end

    reserve!(encrypted1, 3)
    time_multiply_sum += @elapsedus multiply_inplace!(encrypted1, encrypted2, evaluator)

    time_multiply_plain_sum += @elapsedus multiply_plain_inplace!(encrypted2, plain, evaluator)

    time_square_sum += @elapsedus square_inplace!(encrypted2, evaluator)

    if using_keyswitching(context)
      time_relinearize_sum += @elapsedus relinearize_inplace!(encrypted1, relin_keys_, evaluator)

      time_rotate_rows_one_step_sum += @elapsedus begin
        rotate_rows_inplace!(encrypted,  1, galois_keys_, evaluator)
        rotate_rows_inplace!(encrypted, -1, galois_keys_, evaluator)
      end

      row_size = div(slot_count(batch_encoder), 2)
      random_rotation = rand(RandomDevice(), Int64) .% row_size
      time_rotate_rows_random_sum += @elapsedus begin
        rotate_rows_inplace!(encrypted, random_rotation, galois_keys_, evaluator)
      end

      time_rotate_columns_sum += @elapsedus begin
        rotate_columns_inplace!(encrypted, galois_keys_, evaluator)
      end
    end

    print(".")
    flush(stdout)
  end

  println(" Done")
  println()

  avg_batch = div(time_batch_sum, count)
  avg_unbatch = div(time_unbatch_sum, count)
  avg_encrypt = div(time_encrypt_sum, count)
  avg_decrypt = div(time_decrypt_sum, count)
  avg_add = div(time_add_sum, (3 * count))
  avg_multiply = div(time_multiply_sum, count)
  avg_multiply_plain = div(time_multiply_plain_sum, count)
  avg_square = div(time_square_sum, count)
  avg_relinearize = div(time_relinearize_sum, count)
  avg_rotate_rows_one_step = div(time_rotate_rows_one_step_sum, (2 * count))
  avg_rotate_rows_random = div(time_rotate_rows_random_sum, count)
  avg_rotate_columns = div(time_rotate_columns_sum, count)

  println("Average batch: ", avg_batch, " microseconds")
  println("Average unbatch: ", avg_unbatch, " microseconds")
  println("Average encrypt: ", avg_encrypt, " microseconds")
  println("Average decrypt: ", avg_decrypt, " microseconds")
  println("Average add: ", avg_add, " microseconds")
  println("Average multiply: ", avg_multiply, " microseconds")
  println("Average multiply plain: ", avg_multiply_plain, " microseconds")
  println("Average square: ", avg_square, " microseconds")
  if using_keyswitching(context)
    println("Average relinearize: ", avg_relinearize, " microseconds")
    println("Average rotate rows one step: ", avg_rotate_rows_one_step, " microseconds")
    println("Average rotate rows random: ", avg_rotate_rows_random, " microseconds")
    println("Average rotate columns: ", avg_rotate_columns, " microseconds")
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
