@testset "4_ckks_basics" begin
  @testset "EncryptionParameters" begin
    @test_nowarn EncryptionParameters(SchemeType.CKKS)
  end
  enc_parms = EncryptionParameters(SchemeType.CKKS)

  @testset "polynomial modulus degree" begin
    @test_nowarn set_poly_modulus_degree!(enc_parms, 8192)
    @test poly_modulus_degree(enc_parms) == 8192
  end

  @testset "coefficient modulus" begin
    @test_nowarn coeff_modulus_create(8192, [60, 40, 40, 60])
    @test_nowarn set_coeff_modulus!(enc_parms, coeff_modulus_create(8192, [60, 40, 40, 60]))
  end

  @testset "SEALContext" begin
    @test_nowarn SEALContext(enc_parms)
  end
  context = SEALContext(enc_parms)

  @testset "extract parameters" begin
    @test_nowarn key_context_data(context)
    context_data = key_context_data(context)
    @test_nowarn parms(context_data)
    ec = parms(context_data)
    @test scheme(ec) == SchemeType.CKKS
    @test total_coeff_modulus_bit_count(context_data) == 200
    @test_nowarn coeff_modulus(ec)
    bit_counts = [bit_count(modulus) for modulus in coeff_modulus(ec)]
    @test bit_counts == [60, 40, 40, 60]
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

  @testset "CKKSEncoder" begin
    @test_nowarn CKKSEncoder(context)
  end
  encoder = CKKSEncoder(context)

  slot_count_ = 4096
  @testset "slot_count" begin
    @test slot_count(encoder) == slot_count_
  end

  @testset "Plaintext" begin
    @test_nowarn Plaintext()
  end
  plain_coeff3 = Plaintext()
  plain_coeff1 = Plaintext()
  plain_coeff0 = Plaintext()
  x_plain = Plaintext()

  input = collect(range(0.0, 1.0, length=slot_count_))
  initial_scale = 2.0^40
  @testset "encode!" begin
    @test_nowarn encode!(plain_coeff3, 3.14159265, initial_scale, encoder)
    @test_nowarn encode!(plain_coeff1, 0.4, initial_scale, encoder)
    @test_nowarn encode!(plain_coeff0, 1.0, initial_scale, encoder)
    @test_nowarn encode!(x_plain, input, initial_scale, encoder)
  end

  @testset "Ciphertext" begin
    @test_nowarn Ciphertext()
  end
  x1_encrypted = Ciphertext()

  @testset "encrypt!" begin
    @test_nowarn encrypt!(x1_encrypted, x_plain, encryptor)
  end

  x3_encrypted = Ciphertext()
  @testset "square!" begin
    @test_nowarn square!(x3_encrypted, x1_encrypted, evaluator)
  end

  @testset "relinearize_inplace!" begin
    @test_nowarn relinearize_inplace!(x3_encrypted, relin_keys_, evaluator)
  end

  @testset "scale (before rescaling)" begin
    @test isapprox(log2(scale(x3_encrypted)), 80)
  end

  @testset "rescale_to_next_inplace!" begin
    @test rescale_to_next_inplace!(x3_encrypted, evaluator) == x3_encrypted
  end

  @testset "scale (after rescaling)" begin
    @test isapprox(log2(scale(x3_encrypted)), 40)
  end

  x1_encrypted_coeff3 = Ciphertext()
  @testset "multiply_plain! and rescale" begin
    @test_nowarn multiply_plain!(x1_encrypted_coeff3, x1_encrypted, plain_coeff3, evaluator)
    @test_nowarn rescale_to_next_inplace!(x1_encrypted_coeff3, evaluator)
  end

  @testset "multiply_inplace!" begin
    @test multiply_inplace!(x3_encrypted, x1_encrypted_coeff3, evaluator) == x3_encrypted
  end

  @testset "relinearize_inplace! and rescale" begin
    @test_nowarn relinearize_inplace!(x3_encrypted, relin_keys_, evaluator)
    @test_nowarn rescale_to_next_inplace!(x3_encrypted, evaluator)
  end

  @testset "multiply_plain_inplace! and rescale" begin
    @test_nowarn multiply_plain_inplace!(x1_encrypted, plain_coeff1, evaluator)
    @test_nowarn rescale_to_next_inplace!(x1_encrypted, evaluator)
  end

  @testset "parms_id" begin
    @test parms_id(x3_encrypted) == UInt64[0x2af33fda5cee1476, 0xe1a78ed1ec9d76b3,
                                           0xed2adee911ba7c4d, 0x94f949f4f9055b1a]
    @test parms_id(x1_encrypted) == UInt64[0xdc264f695a81d156, 0x890465c10f20b410,
                                           0xf03d86f8bc932745, 0x2e67b09e17d4a44c]
    @test parms_id(plain_coeff0) == UInt64[0x12a009457dbf8b0f, 0x6364d5f3d4c92b3c,
                                           0x96a841ccd88e440c, 0x1255677018089458]
  end
  pid1 = parms_id(x3_encrypted)
  pid2 = parms_id(x1_encrypted)
  pid3 = parms_id(plain_coeff0)

  @testset "get_context_data" begin
    @test_nowarn get_context_data(context, pid1)
    @test_nowarn get_context_data(context, pid2)
    @test_nowarn get_context_data(context, pid3)
  end
  cd1 = get_context_data(context, pid1)
  cd2 = get_context_data(context, pid2)
  cd3 = get_context_data(context, pid3)

  @testset "chain_index" begin
    @test chain_index(cd1) == 0
    @test chain_index(cd2) == 1
    @test chain_index(cd3) == 2
  end

  @testset "scale!" begin
    @test_nowarn scale!(x3_encrypted, 2.0^40)
    @test_nowarn scale!(x1_encrypted, 2.0^40)
  end

  last_parms_id = parms_id(x3_encrypted)
  @testset "mod_switch_to_inplace!" begin
    @test mod_switch_to_inplace!(x1_encrypted, last_parms_id, evaluator) == x1_encrypted
    @test mod_switch_to_inplace!(plain_coeff0, last_parms_id, evaluator) == plain_coeff0
  end

  encrypted_result = Ciphertext()
  @testset "add!" begin
    @test_nowarn add!(encrypted_result, x3_encrypted, x1_encrypted, evaluator)
  end

  @testset "add_plain_inplace!" begin
    @test_nowarn add_plain_inplace!(encrypted_result, plain_coeff0, evaluator)
  end

  plain_result = Plaintext()
  @testset "decrypt!" begin
    @test_nowarn decrypt!(plain_result, encrypted_result, decryptor)
  end

  result = similar(input)
  @testset "decode!" begin
    @test_nowarn decode!(result, plain_result, encoder)
  end

  @testset "compare results" begin
    true_result = similar(input)
    for (i, x) in enumerate(input)
      true_result[i] = (3.14159265 * x * x + 0.4) * x + 1
    end
    @test isapprox(result, true_result, atol=1e-4)
  end
end

