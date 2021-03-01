include("utilities.jl")

using SEAL
using Printf


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
    enc_parms = EncryptionParameters(SchemeType.ckks)
    poly_modulus_degree = 8192
    set_poly_modulus_degree!(enc_parms, poly_modulus_degree)
    set_coeff_modulus!(enc_parms, coeff_modulus_create(poly_modulus_degree, [50, 20, 50]))

    resize!(parms_stream, save_size(enc_parms))
    out_bytes = save!(parms_stream, enc_parms)
    resize!(parms_stream, out_bytes)

    print_line(@__LINE__)
    println("EncryptionParameters: wrote ", out_bytes, " bytes")

    print_line(@__LINE__)
    println("EncryptionParameters: data size upper bound (compr_mode_type::none): ",
            save_size(ComprModeType.none, enc_parms))
    println("             EncryptionParameters: data size upper bound (compr_mode_type::deflate): ",
            save_size(ComprModeType.deflate, enc_parms))

    byte_buffer = Vector{UInt8}(undef, save_size(enc_parms))
    save!(byte_buffer, length(byte_buffer), enc_parms)

    enc_parms2 = EncryptionParameters()
    load!(enc_parms2, byte_buffer, length(byte_buffer))

    print_line(@__LINE__)
    println("EncryptionParameters: parms == parms2: ", enc_parms == enc_parms2)
  end

  # Client
  let
    enc_parms = EncryptionParameters()
    load!(enc_parms, parms_stream)

    context = SEALContext(enc_parms)

    keygen = KeyGenerator(context)
    pk = PublicKey()
    create_public_key!(pk, keygen)
    sk = secret_key(keygen)

    resize!(sk_stream, save_size(sk))
    out_bytes = save!(sk_stream, sk)
    resize!(sk_stream, out_bytes)

    rlk = create_relin_keys(keygen)

    resize!(data_stream1, save_size(rlk))
    size_rlk = save!(data_stream1, rlk)
    resize!(data_stream1, size_rlk)

    rlk_big = RelinKeys()
    create_relin_keys!(rlk_big, keygen)
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
    encrypted2 = Ciphertext()
    encrypt!(encrypted1, plain1, encryptor)
    encrypt!(encrypted2, plain2, encryptor)

    sym_encryptor = Encryptor(context, sk)
    sym_encrypted1 = encrypt_symmetric(plain1, sym_encryptor)
    sym_encrypted2 = encrypt_symmetric(plain2, sym_encryptor)

    resize!(data_stream2, save_size(sym_encrypted1))
    size_sym_encrypted1 = save!(data_stream2, sym_encrypted1)
    resize!(data_stream2, size_sym_encrypted1)
    resize!(data_stream3, save_size(encrypted1))
    size_encrypted1 = save!(data_stream3, encrypted1)
    resize!(data_stream3, size_encrypted1)

    print_line(@__LINE__)
    println("Serializable<Ciphertext> (symmetric-key): wrote ", size_sym_encrypted1, " bytes")
    println("             ", "Ciphertext (public-key): wrote ", size_encrypted1, " bytes")

    resize!(data_stream3, save_size(sym_encrypted2))
    size_sym_encrypted2 = save!(data_stream3, sym_encrypted2)
    resize!(data_stream3, size_sym_encrypted2)
  end

  # Server
  let
    enc_parms = EncryptionParameters()
    load!(enc_parms, parms_stream)
    context = SEALContext(enc_parms)

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
    println("Ciphertext (symmetric-key): wrote ", size_encrypted_prod, " bytes")
  end

  # Client
  let
    enc_parms = EncryptionParameters()
    load!(enc_parms, parms_stream)
    context = SEALContext(enc_parms)

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
  println("             ", "Size indicated in SEALHeader: ", header.size, " bytes")
  println()

  return
end
