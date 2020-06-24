
"""
    version_major()

Return the *major* version of the used SEAL library as an integer.

See also: [`version_minor`](@ref), [`version_patch`](@ref), [`version`](@ref)
"""
function version_major()
  val = Ref{UInt8}(0)
  retval = ccall((:Version_Major, libsealc), Clong, (Ref{UInt8},), val)
  @check_return_value retval
  return convert(Int, val[])
end

"""
    version_minor()

Return the *minor* version of the used SEAL library as an integer.

See also: [`version_major`](@ref), [`version_patch`](@ref), [`version`](@ref)
"""
function version_minor()
  val = Ref{UInt8}(0)
  retval = ccall((:Version_Minor, libsealc), Clong, (Ref{UInt8},), val)
  @check_return_value retval
  return convert(Int, val[])
end

"""
    version_patch()

Return the *patch* version of the used SEAL library as an integer.

See also: [`version_major`](@ref), [`version_minor`](@ref), [`version`](@ref)
"""
function version_patch()
  val = Ref{UInt8}(0)
  retval = ccall((:Version_Patch, libsealc), Clong, (Ref{UInt8},), val)
  @check_return_value retval
  return convert(Int, val[])
end

"""
    version()

Return the version of the used SEAL library as a `VersionNumber` in the format
`v"major.minor.patch"`..

See also: [`version_major`](@ref), [`version_minor`](@ref), [`version_patch`](@ref)
"""
function version()
  major = version_major()
  minor = version_minor()
  patch = version_patch()
  return VersionNumber("$major.$minor.$patch")
end
