{
  description = "OpenID Connect 1.0 in Haskell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    haskellrc.url = "github:pjones/haskellrc";
    haskellrc.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, ... }@inputs:
    let
      # The name of the Haskell package:
      packageName = "openid-connect";

      # Haskell package overrides:
      packageOverrides = haskell: {
        jose = haskell.jose_0_10;
      };

      # List of supported compilers:
      supportedCompilers = [
        "ghc8107"
        "ghc902"
        "ghc925"
        "ghc944"
      ];

      # List of supported systems:
      supportedSystems = [ "x86_64-linux" ];

      # Function to generate a set based on supported systems:
      forAllSystems = f:
        nixpkgs.lib.genAttrs supportedSystems (system: f system);

      # Attribute set of nixpkgs for each system:
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; });

      # A source file list cleaner for Haskell programs:
      haskellSourceFilter = src:
        nixpkgs.lib.cleanSourceWith {
          inherit src;
          filter = name: type:
            let baseName = baseNameOf (toString name); in
            nixpkgs.lib.cleanSourceFilter name type &&
            !(
              baseName == "dist-newstyle"
              || nixpkgs.lib.hasPrefix "." baseName
            );
        };

      # The package derivation:
      derivation = haskell:
        haskell.callCabal2nix
          packageName
          (haskellSourceFilter ./.)
          (packageOverrides haskell);

      # Development environment:
      shell = pkgs: haskell:
        haskell.shellFor {
          NIX_PATH = "nixpkgs=${pkgs.path}";

          packages = _: [ self.packages.${pkgs.system}.${packageName} ];
          withHoogle = true;
          buildInputs = [
            haskell.cabal-fmt
            haskell.cabal-install
            haskell.haskell-language-server
            haskell.hlint
            haskell.ormolu
            inputs.haskellrc.packages.${pkgs.system}.default
          ];
        };
    in
    {
      packages = forAllSystems (system:
        let pkgs = nixpkgsFor.${system}; in
        {
          # The full Haskell package for the default compiler:
          ${packageName} = derivation pkgs.haskellPackages;

          # Just the executables for the default compiler:
          default = pkgs.haskell.lib.justStaticExecutables (derivation pkgs.haskellPackages);
        } // builtins.listToAttrs (map
          (compiler: {
            name = "${packageName}-${compiler}";
            value = derivation pkgs.haskell.packages.${compiler};
          })
          supportedCompilers));

      devShells = forAllSystems (system:
        let pkgs = nixpkgsFor.${system}; in {
          default = shell pkgs pkgs.haskellPackages;
        } // builtins.listToAttrs (map
          (compiler: {
            name = "shell-${compiler}";
            value = shell pkgs pkgs.haskell.packages.${compiler};
          })
          supportedCompilers));
    };
}
