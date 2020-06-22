
function version_major()
  val = Ref{UInt8}(0)
  ccall((:Version_Major, libsealc), Clong, (Ref{UInt8},), val)
  return convert(Int, val[])
end

function version_minor()
  val = Ref{UInt8}(0)
  ccall((:Version_Minor, libsealc), Clong, (Ref{UInt8},), val)
  return convert(Int, val[])
end

function version_patch()
  val = Ref{UInt8}(0)
  ccall((:Version_Patch, libsealc), Clong, (Ref{UInt8},), val)
  return convert(Int, val[])
end

function version()
  major = version_major()
  minor = version_minor()
  patch = version_patch()
  return VersionNumber("$major.$minor.$patch")
end
