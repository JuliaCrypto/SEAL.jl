@testset "2_encoders" begin
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
    relin_keys_ = RelinKeys()
    create_relin_keys!(relin_keys_, keygen)
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
