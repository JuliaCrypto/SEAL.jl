using SEAL
using Test

@testset "SEAL.jl" begin
  @testset "create encryption parameters" begin
    @test_nowarn EncryptionParameters(none)
    @test_nowarn EncryptionParameters(bfv)
    @test_nowarn EncryptionParameters(ckks)
  end

  @testset "get/set polynomial modulus degree" begin
    parms = EncryptionParameters(ckks)
    poly_modulus_degree = 8192
    @test set_poly_modulus_degree!(parms, poly_modulus_degree) == parms
    @test get_poly_modulus_degree(parms) == poly_modulus_degree
  end
end
