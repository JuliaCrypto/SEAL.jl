@testset "6_serialization" begin
  parms_stream = UInt8[]
  data_stream1 = UInt8[]
  data_stream2 = UInt8[]
  data_stream3 = UInt8[]
  data_stream4 = UInt8[]
  sk_stream = UInt8[]

  @testset "server (part 1)" begin
    enc_parms = EncryptionParameters(SchemeType.ckks)
    poly_modulus_degree = 8192
    @testset "polynomial modulus degree" begin
      @test_nowarn set_poly_modulus_degree!(enc_parms, poly_modulus_degree)
    end

    @testset "coefficient modulus" begin
      @test_nowarn set_coeff_modulus!(enc_parms, coeff_modulus_create(poly_modulus_degree, [50, 20, 50]))
    end

    @testset "save! EncryptionParameters" begin
      @test save_size(enc_parms) == 192
      resize!(parms_stream, save_size(enc_parms))
      @test save!(parms_stream, enc_parms) == 75
      out_bytes = 75
      resize!(parms_stream, out_bytes)
    end

    @testset "save_size comparison" begin
      @test save_size(ComprModeType.none, enc_parms) == 129
      @test save_size(ComprModeType.zlib, enc_parms) == 146
    end

    @testset "save! and load! EncryptionParameters" begin
      byte_buffer = Vector{UInt8}(undef, save_size(enc_parms))
      @test save!(byte_buffer, length(byte_buffer), enc_parms) == 75

      enc_parms2 = EncryptionParameters()
      @test load!(enc_parms2, byte_buffer, length(byte_buffer)) == 75
      @test enc_parms == enc_parms2
    end
  end

  @testset "client (part 1)" begin
    enc_parms = EncryptionParameters()
    @testset "load! EncryptionParameters" begin
      @test load!(enc_parms, parms_stream) == 75
    end

    context = SEALContext(enc_parms)
    keygen = KeyGenerator(context)
    pk = PublicKey()
    create_public_key!(pk, keygen)
    sk = secret_key(keygen)

    @testset "save! SecretKey" begin
      @test save_size(sk) == 197464
      resize!(sk_stream, save_size(sk))
      @test isapprox(save!(sk_stream, sk), 145823, rtol=0.01)
      out_bytes = save!(sk_stream, sk)
      resize!(sk_stream, out_bytes)
    end

    rlk = create_relin_keys(keygen)
    @testset "save! create_relin_keys" begin
      @test save_size(rlk) == 395189
      resize!(data_stream1, save_size(rlk))
      @test isapprox(save!(data_stream1, rlk), 291635, rtol=0.01)
      size_rlk = save!(data_stream1, rlk)
      resize!(data_stream1, size_rlk)
    end

    rlk_big = RelinKeys()
    create_relin_keys!(rlk_big, keygen)
    @testset "save! create_relin_keys" begin
      @test save_size(rlk_big) == 789779
      resize!(data_stream2, save_size(rlk_big))
      @test isapprox(save!(data_stream2, rlk_big), 583244, rtol=0.01)
      size_rlk_big = save!(data_stream2, rlk_big)
      resize!(data_stream2, size_rlk_big)
    end

    initial_scale = 2.0^20
    encoder = CKKSEncoder(context)
    plain1 = Plaintext()
    plain2 = Plaintext()

    @testset "encode!" begin
      @test_nowarn encode!(plain1, 2.3, initial_scale, encoder)
      @test_nowarn encode!(plain2, 4.5, initial_scale, encoder)
    end

    encryptor = Encryptor(context, pk)
    encrypted1 = Ciphertext()
    encrypted2 = Ciphertext()
    @testset "encrypt!" begin
      @test_nowarn encrypt!(encrypted1, plain1, encryptor)
      @test_nowarn encrypt!(encrypted2, plain2, encryptor)
    end

    @testset "symmetric encryptor" begin
      @test_nowarn Encryptor(context, sk)
    end
    sym_encryptor = Encryptor(context, sk)

    @testset "encrypt_symmetric, encrypt_symmetric!" begin
      @test encrypt_symmetric(plain1, sym_encryptor) isa Ciphertext
      @test encrypt_symmetric(plain2, sym_encryptor) isa Ciphertext
      c = Ciphertext()
      @test encrypt_symmetric!(c, plain2, sym_encryptor)  == c
    end
    sym_encrypted1 = encrypt_symmetric(plain1, sym_encryptor)
    sym_encrypted2 = encrypt_symmetric(plain2, sym_encryptor)

    @testset "save! Ciphertext" begin
      @test save_size(sym_encrypted1) == 131770
      resize!(data_stream2, save_size(sym_encrypted1))
      @test isapprox(save!(data_stream2, sym_encrypted1), 87070, rtol=0.01)
      size_sym_encrypted1 = save!(data_stream2, sym_encrypted1)
      resize!(data_stream2, size_sym_encrypted1)

      @test save_size(encrypted1) == 263273
      resize!(data_stream3, save_size(encrypted1))
      @test isapprox(save!(data_stream3, encrypted1), 173531, rtol=0.01)
      size_encrypted1 = save!(data_stream3, encrypted1)
      resize!(data_stream3, size_encrypted1)

      @test save_size(sym_encrypted2) == 131770
      resize!(data_stream3, save_size(sym_encrypted2))
      @test isapprox(save!(data_stream3, sym_encrypted2), 86966, rtol=0.01)
      size_sym_encrypted2 = save!(data_stream3, sym_encrypted2)
      resize!(data_stream3, size_sym_encrypted2)
    end
  end

  @testset "server (part 2)" begin
    enc_parms = EncryptionParameters()
    @testset "load! EncryptionParameters" begin
      @test load!(enc_parms, parms_stream) == 75
    end

    context = SEALContext(enc_parms)
    evaluator = Evaluator(context)
    rlk = RelinKeys()
    encrypted1 = Ciphertext()
    encrypted2 = Ciphertext()

    @testset "load! RelinKeys" begin
      @test isapprox(load!(rlk, context, data_stream1), 291635, rtol=0.01)
    end

    @testset "load! Ciphertext" begin
      @test isapprox(load!(encrypted1, context, data_stream2), 87070, rtol=0.01)
      @test isapprox(load!(encrypted2, context, data_stream3), 86966, rtol=0.01)
    end

    encrypted_prod = Ciphertext()
    @testset "multiply, relinearize, rescale" begin
      @test multiply!(encrypted_prod, encrypted1, encrypted2, evaluator) == encrypted_prod
      @test relinearize_inplace!(encrypted_prod, rlk, evaluator) == encrypted_prod
      @test rescale_to_next_inplace!(encrypted_prod, evaluator) == encrypted_prod
    end

    @testset "save! Ciphertext" begin
      @test save_size(encrypted_prod) == 131689
      resize!(data_stream4, save_size(encrypted_prod))
      @test isapprox(save!(data_stream4, encrypted_prod), 117909, rtol=0.01)
      size_encrypted_prod = save!(data_stream4, encrypted_prod)
      resize!(data_stream4, size_encrypted_prod)
    end
  end

  @testset "client (part 2)" begin
    enc_parms = EncryptionParameters()
    load!(enc_parms, parms_stream)
    context = SEALContext(enc_parms)

    sk = SecretKey()
    @testset "load! SecretKey" begin
      @test isapprox(load!(sk, context, sk_stream), 145823, rtol=0.01)
    end

    decryptor = Decryptor(context, sk)
    encoder = CKKSEncoder(context)
    encrypted_result = Ciphertext()
    @testset "load! Ciphertext" begin
      @test_nowarn load!(encrypted_result, context, data_stream4)
    end

    plain_result = Plaintext()
    @testset "decrypt!" begin
      @test_nowarn decrypt!(plain_result, encrypted_result, decryptor)
    end

    slot_count_ = slot_count(encoder)
    result = Vector{Float64}(undef, slot_count_)
    @testset "decode! and check result" begin
      @test_nowarn decode!(result, plain_result, encoder)
      @test isapprox(result[1], 10.35, rtol=0.001)
      @test isapprox(result[2], 10.35, rtol=0.001)
      @test isapprox(result[3], 10.35, rtol=0.001)
      @test isapprox(result[end-2], 10.35, rtol=0.001)
      @test isapprox(result[end-1], 10.35, rtol=0.001)
      @test isapprox(result[end-0], 10.35, rtol=0.001)
    end
  end

  pt = Plaintext("1x^2 + 3")
  stream = Vector{UInt8}(undef, save_size(pt))
  @testset "save! Plaintext" begin
    @test save!(stream, pt) == 66
    data_size = 66
    resize!(stream, data_size)
  end

  header = SEALHeader()
  @testset "load_header!" begin
    @test load_header!(header, stream) == header
    @test header.size == 66
  end
end

