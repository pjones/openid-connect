{ sources ? import ./nix/sources.nix
, pkgs ? import sources.nixpkgs { }
, nix-hs ? import sources.nix-hs { inherit pkgs; }
, ghc ? "default"
, ghcide ? sources.ghcide-nix
, ormolu ? sources.ormolu
}:

nix-hs {
  cabal = ./openid-connect.cabal;
  flags = ["example"];
  compiler = ghc;
  overrides = lib: self: super: with lib; {
    # Version 0.8 has an overly restrictive constraint on base:
    http-media = doJailbreak super.http-media;

    ghcide = import ghcide {};

    ormolu = (import ormolu {
      inherit (lib) pkgs;
      ormoluCompiler = lib.compilerName;
    }).ormolu;
  };
}
