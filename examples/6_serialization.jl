include("utilities.jl")

using SEAL
using Printf


"""
    example_serialization()

Show example for how to use serialization in a client-server setup, where only the client knows the
secret key and the servers does not have knowledge of any unencrypted data.
This function is based on the file `native/examples/6_serialization.cpp` of the original
SEAL library and should yield the exact same output, except for differences in compression ratios.

* [SEAL](https://github.com/microsoft/SEAL)
* [native/examples/6_serialization.cpp](https://github.com/microsoft/SEAL/blob/master/native/examples/6_serialization.cpp)

See also: [`example_bfv_basics`](@ref), [`example_ckks_basics`](@ref)
"""
function example_serialization()
  print_example_banner("Example: Serialization")

  parms_stream = UInt8[]
  data_stream1 = UInt8[]
  data_stream2 = UInt8[]
  data_stream3 = UInt8[]
  data_stream4 = UInt8[]
  sk_stream = UInt8[]

  # Use `let` to create new variable scope to mimic curly braces-delimited blocks in C++

  # Server
  let
    parms = EncryptionParameters(SchemeType.ckks)
    poly_modulus_degree = 8192
    set_poly_modulus_degree!(parms, poly_modulus_degree)
    set_coeff_modulus!(parms, coeff_modulus_create(poly_modulus_degree, [50, 20, 50]))

    resize!(parms_stream, save_size(parms))
    out_bytes = save!(parms_stream, parms)
    resize!(parms_stream, out_bytes)

    print_line(@__LINE__)
    println("EncryptionParameters: wrote ", out_bytes, " bytes")

    print_line(@__LINE__)
    println("EncryptionParameters: data size upper bound (compr_mode_type::none): ",
            save_size(ComprModeType.none, parms))
    println("             EncryptionParameters: data size upper bound (compression): ",
            save_size(parms))

    byte_buffer = Vector{UInt8}(undef, save_size(parms))
    save!(byte_buffer, length(byte_buffer), parms)

    parms2 = EncryptionParameters()
    load!(parms2, byte_buffer, length(byte_buffer))

    print_line(@__LINE__)
    println("EncryptionParameters: parms == parms2: ", parms == parms2)
  end

  # Client
  let
    parms = EncryptionParameters()
    load!(parms, parms_stream)

    context = SEALContext(parms)

    keygen = KeyGenerator(context)
    sk = secret_key(keygen)
    pk = PublicKey()
    create_public_key!(pk, keygen)

    resize!(sk_stream, save_size(sk))
    out_bytes = save!(sk_stream, sk)
    resize!(sk_stream, out_bytes)

    rlk = create_relin_keys(keygen)

    rlk_big = RelinKeys()
    create_relin_keys!(rlk_big, keygen)

    resize!(data_stream1, save_size(rlk))
    size_rlk = save!(data_stream1, rlk)
    resize!(data_stream1, size_rlk)
    resize!(data_stream2, save_size(rlk_big))
    size_rlk_big = save!(data_stream2, rlk_big)
    resize!(data_stream2, size_rlk_big)

    print_line(@__LINE__)
    println("Serializable<RelinKeys>: wrote ", size_rlk, " bytes")
    println("             ", "RelinKeys wrote ", size_rlk_big, " bytes")

    initial_scale = 2.0^20
    encoder = CKKSEncoder(context)
    plain1 = Plaintext()
    plain2 = Plaintext()
    encode!(plain1, 2.3, initial_scale, encoder)
    encode!(plain2, 4.5, initial_scale, encoder)

    encryptor = Encryptor(context, pk)

    encrypted1 = Ciphertext()
    encrypt!(encrypted1, plain1, encryptor)
    resize!(data_stream2, save_size(encrypted1))
    size_encrypted1 = save!(data_stream2, encrypted1)
    resize!(data_stream2, size_encrypted1)

    set_secret_key!(encryptor, sk)
    sym_encrypted2 = encrypt_symmetric(plain2, encryptor)
    resize!(data_stream3, save_size(sym_encrypted2))
    size_sym_encrypted2 = save!(data_stream3, sym_encrypted2)
    resize!(data_stream3, size_sym_encrypted2)

    print_line(@__LINE__)
    println("Serializable<Ciphertext> (public-key): wrote ", size_encrypted1, " bytes")
    println("             ",
            "Serializable<Ciphertext> (seeded secret-key): wrote ", size_sym_encrypted2, " bytes")
  end

  # Server
  let
    parms = EncryptionParameters()
    load!(parms, parms_stream)
    context = SEALContext(parms)

    evaluator = Evaluator(context)

    rlk = RelinKeys()
    encrypted1 = Ciphertext()
    encrypted2 = Ciphertext()

    load!(rlk, context, data_stream1)
    load!(encrypted1, context, data_stream2)
    load!(encrypted2, context, data_stream3)

    encrypted_prod = Ciphertext()
    multiply!(encrypted_prod, encrypted1, encrypted2, evaluator)
    relinearize_inplace!(encrypted_prod, rlk, evaluator)
    rescale_to_next_inplace!(encrypted_prod, evaluator)

    resize!(data_stream4, save_size(encrypted_prod))
    size_encrypted_prod = save!(data_stream4, encrypted_prod)
    resize!(data_stream4, size_encrypted_prod)

    print_line(@__LINE__)
    println("Ciphertext (secret-key): wrote ", size_encrypted_prod, " bytes")
  end

  # Client
  let
    parms = EncryptionParameters()
    load!(parms, parms_stream)
    context = SEALContext(parms)

    sk = SecretKey()
    load!(sk, context, sk_stream)
    decryptor = Decryptor(context, sk)
    encoder = CKKSEncoder(context)

    encrypted_result = Ciphertext()
    load!(encrypted_result, context, data_stream4)

    plain_result = Plaintext()
    decrypt!(plain_result, encrypted_result, decryptor)
    slot_count_ = slot_count(encoder)
    result = Vector{Float64}(undef, slot_count_)
    decode!(result, plain_result, encoder)

    print_line(@__LINE__)
    println("Result: ")
    print_vector(result, 3, 7)
  end

  pt = Plaintext("1x^2 + 3")
  stream = Vector{UInt8}(undef, save_size(pt))
  data_size = save!(stream, pt)
  resize!(stream, data_size)

  header = SEALHeader()
  load_header!(header, stream)

  print_line(@__LINE__)
  println("Size written to stream: ", data_size, " bytes")
  println("             ",
          "Size indicated in SEALHeader: ", header.size, " bytes")
  println()

  return
end
