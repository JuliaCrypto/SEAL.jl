@testset "3_levels" begin
  @testset "EncryptionParameters" begin
    @test_nowarn EncryptionParameters(SchemeType.BFV)
  end
  enc_parms = EncryptionParameters(SchemeType.BFV)

  @testset "polynomial modulus degree" begin
    @test_nowarn set_poly_modulus_degree!(enc_parms, 8192)
  end
  
  @testset "coefficient modulus" begin
    @test_nowarn set_coeff_modulus!(enc_parms, coeff_modulus_create(8192, [50, 30, 30, 50, 50]))
  end

  @testset "plain modulus" begin
    @test_nowarn set_plain_modulus!(enc_parms, plain_modulus_batching(8192, 20))
  end

  @testset "SEALContext" begin
    @test_nowarn SEALContext(enc_parms)
  end
  context = SEALContext(enc_parms)

  @testset "key_context_data" begin
    @test_nowarn key_context_data(context)
  end
  context_data = key_context_data(context)

  @testset "modulus switching chain (key context data)" begin
    @test chain_index(context_data) == 4
    @test parms_id(context_data) == [0x26d0ad92b6a78b12,
                                     0x667d7d6411d19434,
                                     0x18ade70427566279,
                                     0x84e0aa06442af302]
    @test_nowarn coeff_modulus(parms(context_data))
    primes = coeff_modulus(parms(context_data))
    @test value(primes[1]) == 0x3ffffffef4001
    @test value(primes[2]) == 0x3ffe8001
    @test value(primes[3]) == 0x3fff4001
    @test value(primes[4]) == 0x3fffffffcc001
    @test value(primes[5]) == 0x3ffffffffc001
  end

  @testset "first_context_data" begin
    @test_nowarn first_context_data(context)
  end
  context_data = first_context_data(context)

  @testset "modulus switching chain (first context data)" begin
    @test chain_index(context_data) == 3
    @test parms_id(context_data) == first_parms_id(context)
    @test parms_id(context_data) == [0x211ee2c43ec16b18,
                                     0x2c176ee3b851d741,
                                     0x490eacf1dd5930b3,
                                     0x3212f104b7a60a0c]
    @test_nowarn coeff_modulus(parms(context_data))
    primes = coeff_modulus(parms(context_data))
    @test value(primes[1]) == 0x3ffffffef4001
    @test value(primes[2]) == 0x3ffe8001
    @test value(primes[3]) == 0x3fff4001
    @test value(primes[4]) == 0x3fffffffcc001
  end

  @testset "next_context_data" begin
    @test_nowarn next_context_data(context_data)
  end
  context_data = next_context_data(context_data)
  context_data = next_context_data(context_data)
  context_data = next_context_data(context_data)
  @testset "isnothing(next_context_data)" begin
    @test isnothing(next_context_data(context_data))
  end

  @testset "modulus switching chain (last context data)" begin
    @test chain_index(context_data) == 0
    @test parms_id(context_data) == last_parms_id(context)
    @test parms_id(context_data) == [0xaf7f6dac55528cf7,
                                     0x2f532a7e2362ab73,
                                     0x03aeaedd1059515e,
                                     0xa515111177a581ca]
    @test_nowarn coeff_modulus(parms(context_data))
    primes = coeff_modulus(parms(context_data))
    @test value(primes[1]) == 0x3ffffffef4001
  end

  keygen = KeyGenerator(context)
  public_key_ = public_key(keygen)
  secret_key_ = secret_key(keygen)
  relin_keys_ = relin_keys_local(keygen)
  galois_keys_ = galois_keys_local(keygen)

  @testset "parms_id of generated keys" begin
    p = [0x26d0ad92b6a78b12, 0x667d7d6411d19434, 0x18ade70427566279, 0x84e0aa06442af302]
    @test parms_id(public_key_) == p
    @test parms_id(secret_key_) == p
    @test parms_id(relin_keys_) == p
    @test parms_id(galois_keys_) == p
  end

  encryptor = Encryptor(context, public_key_)
  evaluator = Evaluator(context)
  decryptor = Decryptor(context, secret_key_)

  @testset "Plaintext" begin
    @test_nowarn Plaintext("1x^3 + 2x^2 + 3x^1 + 4")
  end
  plain = Plaintext("1x^3 + 2x^2 + 3x^1 + 4")

  encrypted = Ciphertext()
  encrypt!(encrypted, plain, encryptor)

  @testset "parms_id of plain" begin
    @test parms_id(plain) == [0x0000000000000000,
                              0x0000000000000000,
                              0x0000000000000000,
                              0x0000000000000000]
  end

  @testset "parms_id of encrypted" begin
    @test parms_id(encrypted) == [0x211ee2c43ec16b18,
                                  0x2c176ee3b851d741,
                                  0x490eacf1dd5930b3,
                                  0x3212f104b7a60a0c]
  end

  @testset "modulus switching on encrypted (level 3)" begin
    context_data = first_context_data(context)
    @test chain_index(context_data) == 3
    @test parms_id(context_data) == [0x211ee2c43ec16b18,
                                     0x2c176ee3b851d741,
                                     0x490eacf1dd5930b3,
                                     0x3212f104b7a60a0c]
    @test invariant_noise_budget(encrypted, decryptor) in (131, 132, 133)
  end

  @testset "modulus switching on encrypted (level 2)" begin
    @test mod_switch_to_next_inplace!(encrypted, evaluator) == encrypted
    context_data = next_context_data(context_data)
    @test chain_index(context_data) == 2
    @test parms_id(context_data) == [0x85626ad91458073f,
                                     0xe186437698f5ff4e,
                                     0xa1e71da26dabe039,
                                     0x9b66f4ab523b9be1]
    @test invariant_noise_budget(encrypted, decryptor) in (81, 82, 83)
  end

  @testset "modulus switching on encrypted (level 1)" begin
    @test mod_switch_to_next_inplace!(encrypted, evaluator) == encrypted
    context_data = next_context_data(context_data)
    @test chain_index(context_data) == 1
    @test parms_id(context_data) == [0x73b7dc26d10a15b9,
                                     0x56ce8bdd07324dfa,
                                     0x7ff7b8ec16a6f20f,
                                     0xb80f7319f2a28ac1]
    @test invariant_noise_budget(encrypted, decryptor) in (51, 52, 53)
  end

  @testset "modulus switching on encrypted (level 3)" begin
    @test mod_switch_to_next_inplace!(encrypted, evaluator) == encrypted
    context_data = next_context_data(context_data)
    @test chain_index(context_data) == 0
    @test parms_id(context_data) == [0xaf7f6dac55528cf7,
                                     0x2f532a7e2362ab73,
                                     0x03aeaedd1059515e,
                                     0xa515111177a581ca]
    @test invariant_noise_budget(encrypted, decryptor) in (21, 22, 23)
  end

  @testset "decrypt! and check 1" begin
    @test_nowarn decrypt!(plain, encrypted, decryptor)
    @test to_string(plain) == "1x^3 + 2x^2 + 3x^1 + 4"
  end

  @testset "compute with modswitching" begin
    @test_nowarn encrypt!(encrypted, plain, encryptor)
    @test invariant_noise_budget(encrypted, decryptor) in (131, 132, 133)

    @test square_inplace!(encrypted, evaluator) == encrypted
    @test relinearize_inplace!(encrypted, relin_keys_, evaluator) == encrypted
    @test invariant_noise_budget(encrypted, decryptor) in (99, 100, 101)

    @test square_inplace!(encrypted, evaluator) == encrypted
    @test relinearize_inplace!(encrypted, relin_keys_, evaluator) == encrypted
    @test invariant_noise_budget(encrypted, decryptor) in (66, 67, 68)

    @test_nowarn mod_switch_to_next_inplace!(encrypted, evaluator)
    @test invariant_noise_budget(encrypted, decryptor) in (66, 67, 68)

    @test square_inplace!(encrypted, evaluator) == encrypted
    @test relinearize_inplace!(encrypted, relin_keys_, evaluator) == encrypted
    @test invariant_noise_budget(encrypted, decryptor) in (33, 34, 35)

    @test_nowarn mod_switch_to_next_inplace!(encrypted, evaluator)
    @test invariant_noise_budget(encrypted, decryptor) in (33, 34, 35)
  end

  @testset "decrypt! and check 2" begin
    @test_nowarn decrypt!(plain, encrypted, decryptor)
    @test to_string(plain) == "1x^24 + 10x^23 + 88x^22 + 330x^21 + EFCx^20 + 3A30x^19 + C0B8x^18 + 22BB0x^17 + 58666x^16 + C88D0x^15 + 9C377x^14 + F4C0Ex^13 + E8B38x^12 + 5EE89x^11 + F8BFFx^10 + 30304x^9 + 5B9D4x^8 + 12653x^7 + 4DFB5x^6 + 879F8x^5 + 825FBx^4 + F1FFEx^3 + 3FFFFx^2 + 60000x^1 + 10000"
  end

  @testset "context without expanded modulus chain" begin
    @test_nowarn SEALContext(enc_parms, expand_mod_chain=false)
  end
  context = SEALContext(enc_parms, expand_mod_chain=false)

  context_data = key_context_data(context)
  @testset "modulus switching chain (chain index 1)" begin
    @test chain_index(context_data) == 1
    @test parms_id(context_data) == [0x26d0ad92b6a78b12,
                                     0x667d7d6411d19434,
                                     0x18ade70427566279,
                                     0x84e0aa06442af302]
    @test_nowarn coeff_modulus(parms(context_data))
    primes = coeff_modulus(parms(context_data))
    @test value(primes[1]) == 0x3ffffffef4001
    @test value(primes[2]) == 0x3ffe8001
    @test value(primes[3]) == 0x3fff4001
    @test value(primes[4]) == 0x3fffffffcc001
  end

  context_data = next_context_data(context_data)
  @testset "modulus switching chain (chain index 0)" begin
    @test chain_index(context_data) == 0
    @test parms_id(context_data) == [0x211ee2c43ec16b18,
                                     0x2c176ee3b851d741,
                                     0x490eacf1dd5930b3,
                                     0x3212f104b7a60a0c]
    @test_nowarn coeff_modulus(parms(context_data))
    primes = coeff_modulus(parms(context_data))
    @test value(primes[1]) == 0x3ffffffef4001
    @test value(primes[2]) == 0x3ffe8001
    @test value(primes[3]) == 0x3fff4001
  end

end

