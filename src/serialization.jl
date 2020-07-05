
module ComprModeType
@enum ComprModeTypeEnum::UInt8 none=0 deflate=1
const default = deflate
end

mutable struct SEALHeader
  magic::UInt16
  header_size::UInt8
  version_major::UInt8
  version_minor::UInt8
  compr_mode::UInt8
  reserved::UInt16
  size::UInt64
end

SEALHeader() = SEALHeader(0, 0, 0, 0, 0, 0, 0)

function load_header!(header::SEALHeader, buffer::DenseVector{UInt8})
  io = IOBuffer(buffer)
  header.magic = read(io, UInt16)
  header.header_size = read(io, UInt8)
  header.version_major = read(io, UInt8)
  header.version_minor = read(io, UInt8)
  header.compr_mode = read(io, UInt8)
  header.reserved = read(io, UInt16)
  header.size = read(io, UInt64)
  return header
end
