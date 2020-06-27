# Additional tests to cover missing pieces
@testset "additional tests" begin
  @testset "version_{major,minor,patch}" begin
    @test_nowarn version_major()
    @test_nowarn version_minor()
    @test_nowarn version_patch()
    @test_nowarn version()
  end

  @testset "version" begin
    major = version_major()
    minor = version_minor()
    patch = version_patch()
    @test version() == VersionNumber("$major.$minor.$patch")
  end

  @testset "PublicKey" begin
    @test_nowarn PublicKey()
  end

  @testset "SecretKey" begin
    @test_nowarn SecretKey()
  end

  @testset "RelinKeys" begin
    @test_nowarn RelinKeys()
  end

  @testset "GaloisKeys" begin
    @test_nowarn GaloisKeys()
  end

  @testset "Modulus" begin
    @test_nowarn Modulus(0)
    @test_throws ErrorException Modulus(1)
    m = Modulus(0)
    @test value(m) == 0
  end

  @testset "memory_manager_get_pool" begin
    @test_nowarn memory_manager_get_pool()
  end

  @testset "check_return_value" begin
    @test_throws ErrorException SEAL.check_return_value(0x80004003)
    @test_throws ErrorException SEAL.check_return_value(0x80070057)
    @test_throws ErrorException SEAL.check_return_value(0x8007000E)
    @test_throws ErrorException SEAL.check_return_value(0x8000FFFF)
    @test_throws ErrorException SEAL.check_return_value(0x80131620)
    @test_throws ErrorException SEAL.check_return_value(0x80131509)
    @test_throws ErrorException SEAL.check_return_value(0x11111111)
  end

  enc_parms = EncryptionParameters(SchemeType.CKKS)
  set_poly_modulus_degree!(enc_parms, 8192)
  set_coeff_modulus!(enc_parms, coeff_modulus_create(8192, [60, 40, 40, 60]))
  context = SEALContext(enc_parms)
  keygen = KeyGenerator(context)
  public_key_ = public_key(keygen)
  secret_key_ = secret_key(keygen)
  @testset "Encryptor" begin
    @test_nowarn Encryptor(context, public_key_, secret_key_)
    @test_nowarn Encryptor(context, public_key_)
    @test_nowarn Encryptor(context, secret_key_)
  end

  @testset "scale/scale! Plaintext" begin
    p = Plaintext()
    @test isapprox(scale(p), 1.0)
    @test_nowarn scale!(p, 2.0^40)
    @test isapprox(scale(p), 2.0^40)
  end

  @testset "relin_keys" begin
    @test_nowarn relin_keys(keygen)
  end

  @testset "plain_modulus" begin
    @test_nowarn plain_modulus(enc_parms)
  end

  p = Plaintext()
  encoder = CKKSEncoder(context)
  encode!(p, 3.14159265, 2.0^40, encoder) 
  encryptor = Encryptor(context, public_key_)
  evaluator = Evaluator(context)
  relin_keys_ = relin_keys_local(keygen)
  @testset "{square,relinearize,rescale_to_next}_inplace!" begin
    c1 = Ciphertext()
    encrypt!(c1, p, encryptor)
    @test_nowarn typeof(square_inplace!(c1, evaluator)) === Ciphertext
    @test_nowarn typeof(relinearize_inplace!(c1, relin_keys_, evaluator)) === Ciphertext
    @test_nowarn typeof(rescale_to_next_inplace!(c1, evaluator)) === Ciphertext
  end

  @testset "multiply_plain_inplace!" begin
    c2 = Ciphertext()
    encrypt!(c2, p, encryptor)
    @test_nowarn multiply_plain_inplace!(c2, p, evaluator)
  end

  @testset "multiply_inplace!" begin
    c3 = Ciphertext()
    c4 = Ciphertext()
    encrypt!(c3, p, encryptor)
    encrypt!(c4, p, encryptor)
    @test_nowarn multiply_inplace!(c3, c4, evaluator)
  end

  @testset "add_inplace!" begin
    c5 = Ciphertext()
    c6 = Ciphertext()
    encrypt!(c5, p, encryptor)
    encrypt!(c6, p, encryptor)
    @test_nowarn add_inplace!(c5, c6, evaluator)
  end

  @testset "add_plain_inplace!" begin
    c7 = Ciphertext()
    encrypt!(c7, p, encryptor)
    @test_nowarn add_plain_inplace!(c7, p, evaluator)
  end

  galois_keys_ = galois_keys_local(keygen)
  @testset "rotate_vector_inplace!" begin
    c8 = Ciphertext()
    encrypt!(c8, p, encryptor)
    @test_nowarn rotate_vector_inplace!(c8, 5, galois_keys_, evaluator)
  end
end

