using Documenter
import Pkg

# Get root directory
root_dir = dirname(@__DIR__)

# Install dependencies and import modules...
Pkg.activate(root_dir)
Pkg.instantiate()
using SEAL

# Define module-wide setups such that the respective modules are available in doctests
DocMeta.setdocmeta!(SEAL,
                    :DocTestSetup,
                    :(push!(LOAD_PATH, ".."); using SEAL);
                    recursive=true)

# Make documentation
makedocs(
    # Specify modules for which docstrings should be shown
    modules = [SEAL],
    # Set sitename to SEAL
    sitename = "SEAL.jl",
    # Set authors
    authors = "Michael Schlottke-Lakemper",
    # Provide additional formatting options
    format = Documenter.HTML(
        # Disable pretty URLs during manual testing
        prettyurls = get(ENV, "CI", nothing) == "true",
        # Explicitly add favicon as asset
        # assets = ["assets/favicon.ico"],
        # Set canonical URL to GitLab pages URL
        # canonical = canonical
    ),
    # Explicitly specify documentation structure
    pages = [
        "Home" => "index.md",
        "Reference" => "reference.md",
        "Contributing" => "contributing.md",
        "License" => "license.md"
    ],
)

deploydocs(
    repo = "github.com/JuliaCrypto/SEAL.jl.git",
)
