using SEAL
using Test

@testset "SEAL.jl" begin
  @testset "create encryption parameters" begin
    @test_nowarn EncryptionParameters(SchemeType.none)
    @test_nowarn EncryptionParameters(SchemeType.bfv)
    @test_nowarn EncryptionParameters(SchemeType.ckks)
  end

  @testset "get/set polynomial modulus degree" begin
    parms = EncryptionParameters(SchemeType.ckks)
    poly_modulus_degree = 8192
    @test set_poly_modulus_degree!(parms, poly_modulus_degree) == parms
    @test get_poly_modulus_degree(parms) == poly_modulus_degree
  end
end
