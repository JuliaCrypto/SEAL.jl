using CBindingGen
using Libdl
import SEAL_jll

# Generate C bindings
@info "Generate C bindings..."

# Determine library path
seal_path = SEAL_jll.get_libsealc_path() |> dirname |> dirname
@info "SEAL path" seal_path

# For the actual include directory we need to first find the version-specific directory
seal_include = joinpath(seal_path, "include")
function get_version_include(include_dir)
  version_include = ""
  for dir in readdir(seal_include)
    if startswith(dir, "SEAL-")
      version_include = dir
      break
    end
  end
  return version_include
end
version_include = get_version_include(seal_include)
if isempty(version_include)
  error("could not find proper include directory path in $seal_include")
end
seal_include = joinpath(seal_include, version_include)
seal_include_c = joinpath(seal_include, "seal", "c")
include_override = joinpath(@__DIR__, "include_override")
@info "SEAL include directory" seal_include
@info "SEAL C include directory" seal_include_c
@info "include override directory" include_override

# Find header files to consider
# headers = String["helper.h"]
headers = String[]
skip_headers = ["targetver.h"]
for filename in readdir(seal_include_c)
  if !isfile(joinpath(seal_include_c, filename))
    continue
  end
  if !endswith(filename, ".h")
    continue
  end
  if filename in skip_headers
    continue
  end
  push!(headers, joinpath("seal", "c", filename))
end
@info "Header files" headers

# Build list of arguments for Clang
clang_args = String[]
include_directories = [seal_include]
# include_directories = [seal_include, include_override]
for dir in include_directories
  append!(clang_args, ("-I", dir))
end
append!(clang_args, ("-x", "c++", "-std=c++17"))
# append!(clang_args, ("-Dstatic_assert(a...)=", "-Wno-macro-redefined"))
@info "Clang args" clang_args

# Convert symbols in header
@info "Convert symbols in headers to Julia expressions..."
cvts = convert_headers(headers, args=clang_args) do cursor
  header = CodeLocation(cursor).file
  name   = string(cursor)

  # only wrap the SEAL headers
  dirname, filename = splitdir(header)
  qualified_filename = joinpath("seal", "c", filename)
  if !(qualified_filename in headers)
    return false
  end

  @info "converting " qualified_filename

  return true
end

# Write generated C bindings to file
@info "Write generated C bindings to file..."
const bindings_filename = joinpath(@__DIR__, "libsealc.jl")
open(bindings_filename, "w+") do io
  generate(io, SEAL_jll.get_libsealc_path() => cvts)
end
