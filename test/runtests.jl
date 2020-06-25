using SEAL
using Test

# Include files with example-specific tests
include("test_1_bfv_basics.jl")
include("test_4_ckks_basics.jl")
include("test_5_rotation.jl")

# Additional tests to cover missing pieces
@testset "additional tests" begin
  @testset "library version" begin
    @test_nowarn version_major()
    @test_nowarn version_minor()
    @test_nowarn version_patch()
    @test_nowarn version()
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
  end

  @testset "memory_manager_get_pool" begin
    @test_nowarn memory_manager_get_pool()
  end

  @testset "check_return_value" begin
    @test_throws ErrorException check_return_value(0x80004003)
    @test_throws ErrorException check_return_value(0x80070057)
    @test_throws ErrorException check_return_value(0x8007000E)
    @test_throws ErrorException check_return_value(0x8000FFFF)
    @test_throws ErrorException check_return_value(0x80131620)
    @test_throws ErrorException check_return_value(0x80131509)
    @test_throws ErrorException check_return_value(0x11111111)
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
end
