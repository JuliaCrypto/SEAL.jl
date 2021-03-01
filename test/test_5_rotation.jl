@testset "5_rotation" begin
  @testset "rotation_ckks" begin
    @testset "EncryptionParameters" begin
      @test_nowarn EncryptionParameters(SchemeType.CKKS)
    end
    enc_parms = EncryptionParameters(SchemeType.CKKS)

    @testset "polynomial modulus degree" begin
      @test_nowarn set_poly_modulus_degree!(enc_parms, 8192)
      @test poly_modulus_degree(enc_parms) == 8192
    end

    @testset "coefficient modulus" begin
      @test_nowarn coeff_modulus_create(8192, [40, 40, 40, 40, 40])
      @test_nowarn set_coeff_modulus!(enc_parms, coeff_modulus_create(8192, [40, 40, 40, 40, 40]))
    end

    @testset "SEALContext" begin
      @test_nowarn SEALContext(enc_parms)
    end
    context = SEALContext(enc_parms)

    @testset "KeyGenerator" begin
      @test_nowarn KeyGenerator(context)
    end
    keygen = KeyGenerator(context)

    @testset "PublicKey" begin
      @test_nowarn PublicKey()
    end
    public_key_ = PublicKey()

    @testset "create_public_key" begin
      @test_nowarn create_public_key!(public_key_, keygen)
    end

    @testset "SecretKey" begin
      @test_nowarn secret_key(keygen)
    end
    secret_key_ = secret_key(keygen)

    @testset "RelinKeys" begin
      @test_nowarn RelinKeys()
    end
    relin_keys_ = RelinKeys()

    @testset "create_relin_keys" begin
      @test_nowarn create_relin_keys!(relin_keys_, keygen)
    end

    @testset "GaloisKeys" begin
      @test_nowarn GaloisKeys()
    end
    galois_keys_ = GaloisKeys()

    @testset "create_galois_keys" begin
      @test_nowarn create_galois_keys!(galois_keys_, keygen)
    end

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

    input = collect(range(0.0, 1.0, length=slot_count_))
    plain = Plaintext()
    encrypted = Ciphertext()
    initial_scale = 2.0^50
    @testset "encode and encrypt" begin
      @test_nowarn encode!(plain, input, initial_scale, encoder)
      @test_nowarn encrypt!(encrypted, plain, encryptor)
    end

    rotated = Ciphertext()
    @testset "rotate 2 steps left" begin
      @test_nowarn rotate_vector!(rotated, encrypted, 2, galois_keys_, evaluator)
    end

    result = similar(input)
    @testset "decrypt and decode" begin
      @test_nowarn decrypt!(plain, rotated, decryptor)
      @test_nowarn decode!(result, plain, encoder)
    end

    @testset "compare results" begin
      true_result = circshift(input, -2)
      @test isapprox(result, true_result)
    end
  end
end
