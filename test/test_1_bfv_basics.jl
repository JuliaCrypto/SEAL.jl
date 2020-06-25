@testset "1_ckks_basics" begin
  @testset "EncryptionParameters" begin
    @test_nowarn EncryptionParameters(SchemeType.BFV)
  end
  enc_parms = EncryptionParameters(SchemeType.BFV)

  @testset "polynomial modulus degree" begin
    @test_nowarn set_poly_modulus_degree!(enc_parms, 4096)
  end
  
  @testset "coefficient modulus" begin
    @test_nowarn coeff_modulus_bfv_default(4096)
    @test_nowarn set_coeff_modulus!(enc_parms, coeff_modulus_bfv_default(4096))
  end

  @testset "plain modulus" begin
    @test_nowarn set_plain_modulus!(enc_parms, 1024)
  end

  @testset "SEALContext" begin
    @test_nowarn SEALContext(enc_parms)
  end
  context = SEALContext(enc_parms)

  @testset "parameter_error_message" begin
    @test parameter_error_message(context) == "valid"
  end

  @testset "KeyGenerator" begin
    @test_nowarn KeyGenerator(context)
  end
  keygen = KeyGenerator(context)

  @testset "PublicKey" begin
    @test_nowarn public_key(keygen)
  end
  public_key_ = public_key(keygen)

  @testset "SecretKey" begin
    @test_nowarn secret_key(keygen)
  end
  secret_key_ = secret_key(keygen)

  @testset "RelinKeys" begin
    @test_nowarn relin_keys_local(keygen)
  end
  relin_keys_ = relin_keys_local(keygen)

  @testset "Encryptor" begin
    @test_nowarn Encryptor(context, public_key_)
  end
  encryptor = Encryptor(context, public_key_)

  @testset "Evaluator" begin
    @test_nowarn Evaluator(context)
  end
  evaluator = Evaluator(context)

  @testset "Decryptor" begin
    @test_nowarn Decryptor(context, secret_key_)
  end
  decryptor = Decryptor(context, secret_key_)

  @testset "Plaintext" begin
    @test_nowarn Plaintext(string(6))
  end
  x_plain = Plaintext(string(6))

  @testset "to_string" begin
    @test to_string(x_plain) == "6"
  end

  x_encrypted = Ciphertext()
  @testset "encrypt!" begin
    @test_nowarn encrypt!(x_encrypted, x_plain, encryptor)
  end

  @testset "length" begin
    @test length(x_encrypted) == 2
  end

  @testset "invariant_noise_budget" begin
    # Next test is fuzzy since the actual noise budget might vary
    @test invariant_noise_budget(x_encrypted, decryptor) in (54, 55, 56)
  end

  x_decrypted = Plaintext()
  @testset "decrypt!" begin
    @test_nowarn decrypt!(x_decrypted, x_encrypted, decryptor)
    @test to_string(x_decrypted) == "6"
  end

  x_sq_plus_one = Ciphertext()
  @testset "square!" begin
    @test_nowarn square!(x_sq_plus_one, x_encrypted, evaluator)
  end

  plain_one = Plaintext("1")
  @testset "add_plain_inplace! and length/noise budget" begin
    @test_nowarn add_plain_inplace!(x_sq_plus_one, plain_one, evaluator)
    @test length(x_sq_plus_one) == 3
    @test invariant_noise_budget(x_sq_plus_one, decryptor) == 33
  end

  decrypted_result = Plaintext()
  @testset "decrypt! and check (x^2 + 1 = 37 = 0x25)" begin
    @test_nowarn decrypt!(decrypted_result, x_sq_plus_one, decryptor)
    @test to_string(decrypted_result) == "25"
  end

  x_plus_one_sq = Ciphertext()
  @testset "add_plain!" begin
    @test_nowarn add_plain!(x_plus_one_sq, x_encrypted, plain_one, evaluator)
  end

  @testset "square_inplace! and length/noise budget" begin
    @test_nowarn square_inplace!(x_plus_one_sq, evaluator)
    @test length(x_plus_one_sq) == 3
    @test invariant_noise_budget(x_plus_one_sq, decryptor) == 33
  end

  @testset "decrypt! and check ((x+1)^2 = 49 = 0x31)" begin
    @test_nowarn decrypt!(decrypted_result, x_plus_one_sq, decryptor)
    @test to_string(decrypted_result) == "31"
  end

  encrypted_result = Ciphertext()
  plain_four = Plaintext("4")
  @testset "compute encrypted_result (4(x^2+1)(x+1)^2)" begin
    @test_nowarn multiply_plain_inplace!(x_sq_plus_one, plain_four, evaluator)
    @test_nowarn multiply!(encrypted_result, x_sq_plus_one, x_plus_one_sq, evaluator)
    @test length(encrypted_result) == 5
    # Next test is fuzzy since the actual noise budget might vary
    @test invariant_noise_budget(encrypted_result, decryptor) in (3, 4, 5)
  end

  x_squared = Ciphertext()
  @testset "compute and relinearize x_squared (x^2)" begin
    @test_nowarn square!(x_squared, x_encrypted, evaluator)
    @test length(x_squared) == 3
    @test_nowarn relinearize_inplace!(x_squared, relin_keys_, evaluator)
    @test length(x_squared) == 2
  end

  @testset "compute x_sq_plus_one (x^2+1) and decrypt" begin
    @test_nowarn add_plain!(x_sq_plus_one, x_squared, plain_one, evaluator)
    @test invariant_noise_budget(x_sq_plus_one, decryptor) == 33
    @test_nowarn decrypt!(decrypted_result, x_sq_plus_one, decryptor)
    @test to_string(decrypted_result) == "25"
  end

  x_plus_one = Ciphertext()
  @testset "compute x_plus_one (x+1)" begin
    @test_nowarn add_plain!(x_plus_one, x_encrypted, plain_one, evaluator)
  end

  @testset "compute and relinearize x_plus_one_sq ((x+1)^2)" begin
    @test_nowarn square!(x_plus_one_sq, x_plus_one, evaluator)
    @test length(x_plus_one_sq) == 3
    @test_nowarn relinearize_inplace!(x_plus_one_sq, relin_keys_, evaluator)
    @test invariant_noise_budget(x_plus_one_sq, decryptor) == 33
  end

  @testset "decrypt (x+1)^2 and check" begin
    @test_nowarn decrypt!(decrypted_result, x_plus_one_sq, decryptor)
    @test to_string(decrypted_result) == "31"
  end

  @testset "compute and relinearize encrypted_result (4(x^2+1)(x+1)^2)" begin
    @test_nowarn multiply_plain_inplace!(x_sq_plus_one, plain_four, evaluator)
    @test_nowarn multiply!(encrypted_result, x_sq_plus_one, x_plus_one_sq, evaluator)
    @test length(encrypted_result) == 3
    @test_nowarn relinearize_inplace!(encrypted_result, relin_keys_, evaluator)
    @test length(encrypted_result) == 2
    # Next test is fuzzy since the actual noise budget might vary
    @test invariant_noise_budget(encrypted_result, decryptor) in (10, 11, 12)
  end

  @testset "decrypt encrypted_result (4(x^2+1)(x+1)^2) and check" begin
    @test_nowarn decrypt!(decrypted_result, encrypted_result, decryptor)
    @test to_string(decrypted_result) == "54"
  end

  @testset "invalid parameters" begin
    @test_nowarn set_poly_modulus_degree!(enc_parms, 2048)
    context = SEALContext(enc_parms)
    @test parameter_error_message(context) == "parameters are not compliant with HomomorphicEncryption.org security standard"
  end
end

