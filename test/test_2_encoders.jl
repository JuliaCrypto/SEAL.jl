@testset "2_encoders" begin
  @testset "integer_encoder" begin
    parms = EncryptionParameters(SchemeType.BFV)
    poly_modulus_degree = 4096
    set_poly_modulus_degree!(parms, poly_modulus_degree)
    set_coeff_modulus!(parms, coeff_modulus_bfv_default(poly_modulus_degree))

    @testset "set_plain_modulus" begin
      @test set_plain_modulus!(parms, 512) == parms
    end

    context = SEALContext(parms)
    keygen = KeyGenerator(context)
    public_key_ = PublicKey()
    create_public_key!(public_key_, keygen)
    secret_key_ = secret_key(keygen)
    encryptor = Encryptor(context, public_key_)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key_)

    @testset "IntegerEncoder modulus" begin
      @test_nowarn IntegerEncoder(context)
    end
    encoder = IntegerEncoder(context)

    value1 = Int32(5)
    value2 = Int32(-7)
    @testset "encode" begin
      @test_nowarn encode(value1, encoder)
      @test_nowarn encode(value2, encoder)
    end
    plain1 = encode(value1, encoder)
    plain2 = encode(value2, encoder)

    # Extra: encode for other data types
    value3 = UInt32(15)
    @testset "encode (UInt32)" begin
      @test_nowarn encode(value3, encoder)
    end
    value4 = Int64(-19)
    @testset "encode (Int64)" begin
      @test_nowarn encode(value4, encoder)
    end
    value5 = UInt64(15)
    @testset "encode (UInt64)" begin
      @test_nowarn encode(value5, encoder)
    end

    @testset "plain_modulus, value" begin
      @test_nowarn plain_modulus(encoder)
      m = plain_modulus(encoder)
      @test value(m) == 512
    end

    @testset "to_string" begin
      @test to_string(plain1) == "1x^2 + 1"
      @test to_string(plain2) == "1FFx^2 + 1FFx^1 + 1FF"
    end

    encrypted1 = Ciphertext()
    encrypted2 = Ciphertext()

    @testset "encrypt" begin
      @test_nowarn encrypt!(encrypted1, plain1, encryptor)
      @test_nowarn encrypt!(encrypted2, plain2, encryptor)
    end

    @testset "invariant_noise_budget" begin
      @test invariant_noise_budget(encrypted1, decryptor) in (55, 56, 57)
      @test invariant_noise_budget(encrypted2, decryptor) in (55, 56, 57)
    end

    encrypted_result = Ciphertext()
    @testset "encrypted arithmetic" begin
      @test_nowarn negate!(encrypted_result, encrypted1, evaluator)
      @test_nowarn add_inplace!(encrypted_result, encrypted2, evaluator)
      @test_nowarn multiply_inplace!(encrypted_result, encrypted2, evaluator)
    end

    plain_result = Plaintext()
    @testset "decrypt!" begin
      @test_nowarn decrypt!(plain_result, encrypted_result, decryptor)
    end

    @testset "to_string(plain_result)" begin
      @test to_string(plain_result) == "2x^4 + 3x^3 + 5x^2 + 3x^1 + 2"
    end

    @testset "decode_int32" begin
      @test decode_int32(plain_result, encoder) == 84
    end
  end

  @testset "batch_encoder" begin
    parms = EncryptionParameters(SchemeType.BFV)
    poly_modulus_degree = 8192
    set_poly_modulus_degree!(parms, poly_modulus_degree)
    set_coeff_modulus!(parms, coeff_modulus_bfv_default(poly_modulus_degree))
    set_plain_modulus!(parms, plain_modulus_batching(poly_modulus_degree, 20))
    context = SEALContext(parms)

    @testset "first_context_data" begin
      @test_nowarn first_context_data(context)
    end
    context_data = first_context_data(context)

    @testset "qualifiers" begin
      @test_nowarn qualifiers(context_data)
    end
    epq = qualifiers(context_data)

    @testset "using_batches" begin
      @test using_batching(epq) == true
    end

    keygen = KeyGenerator(context)
    public_key_ = PublicKey()
    create_public_key!(public_key_, keygen)
    secret_key_ = secret_key(keygen)
    relin_keys_ = relin_keys_local(keygen)
    encryptor = Encryptor(context, public_key_)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key_)

    @testset "BatchEncoder" begin
      @test_nowarn BatchEncoder(context)
    end
    batch_encoder = BatchEncoder(context)

    @testset "slot_count" begin
      @test slot_count(batch_encoder) == 8192
    end
    slot_count_ = slot_count(batch_encoder)
    row_size = div(slot_count_, 2)

    pod_matrix = zeros(UInt64, slot_count_)
    pod_matrix[1] = 0
    pod_matrix[2] = 1
    pod_matrix[3] = 2
    pod_matrix[4] = 3
    pod_matrix[row_size + 1] = 4
    pod_matrix[row_size + 2] = 5
    pod_matrix[row_size + 3] = 6
    pod_matrix[row_size + 4] = 7

    plain_matrix = Plaintext()
    @testset "encode!" begin
      @test_nowarn encode!(plain_matrix, pod_matrix, batch_encoder)
    end

    pod_result = similar(pod_matrix)
    @testset "decode!" begin
      @test_nowarn decode!(pod_result, plain_matrix, batch_encoder)
    end

    # Extra: encode/decode for Int64 data type
    pod_matrix_int64 = Int64.(pod_matrix)
    plain_matrix_int64 = Plaintext()
    @testset "encode!" begin
      @test_nowarn encode!(plain_matrix_int64, pod_matrix_int64, batch_encoder)
    end
    pod_result_int64 = similar(pod_matrix_int64)
    @testset "decode!" begin
      @test_nowarn decode!(pod_result_int64, plain_matrix_int64, batch_encoder)
    end

    encrypted_matrix = Ciphertext()
    @testset "encrypt!" begin
      @test_nowarn encrypt!(encrypted_matrix, plain_matrix, encryptor)
    end

    @testset "noise budget 1" begin
      @test invariant_noise_budget(encrypted_matrix, decryptor) in (145, 146, 147)
    end

    pod_matrix2 = ones(UInt64, slot_count_)
    pod_matrix2[2:2:slot_count_] .= 2
    plain_matrix2 = Plaintext()

    @testset "encode!" begin
      @test_nowarn encode!(plain_matrix2, pod_matrix2, batch_encoder)
    end

    @testset "sum, square, and relinearize" begin
      @test_nowarn add_plain_inplace!(encrypted_matrix, plain_matrix2, evaluator)
      @test_nowarn square_inplace!(encrypted_matrix, evaluator)
      @test_nowarn relinearize_inplace!(encrypted_matrix, relin_keys_, evaluator)
    end

    @testset "noise budget 2" begin
      @test invariant_noise_budget(encrypted_matrix, decryptor) in (113, 114, 115)
    end

    plain_result = Plaintext()
    @testset "decrypt! and decode!" begin
      @test_nowarn decrypt!(plain_result, encrypted_matrix, decryptor)
      @test_nowarn decode!(pod_result, plain_result, batch_encoder)
    end
  end
end
