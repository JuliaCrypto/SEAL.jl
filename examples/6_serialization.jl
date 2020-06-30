include("utilities.jl")

using SEAL
using Printf


function example_serialization()
  print_example_banner("Example: Serialization")

  parms_stream = UInt8[]
  data_stream = UInt8[]
  sk_stream = UInt8[]

  # Use `let` to create new variable scope to mimic curly braces-delimited blocks in C++

  # Server part
  let
    enc_parms = EncryptionParameters(SchemeType.CKKS)
    poly_modulus_degree = 8192
    set_poly_modulus_degree!(enc_parms, poly_modulus_degree)
    set_coeff_modulus!(enc_parms, coeff_modulus_create(poly_modulus_degree, [50, 20, 50]))

    resize!(parms_stream, save_size(enc_parms))
    out_bytes = save!(parms_stream, enc_parms)

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

  # Client part
  let
    enc_parms = EncryptionParameters()
    load!(enc_parms, parms_stream)

    context = SEALContext(enc_parms)

    keygen = KeyGenerator(context)
    pk = public_key(keygen)
    sk = secret_key(keygen)

    resize!(sk_stream, save_size(sk))
    save!(sk_stream, sk)
  end

  return
end
