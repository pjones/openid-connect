{ sources ? import ./nix/sources.nix
, pkgs ? import sources.nixpkgs { }
, nix-hs ? import sources.nix-hs { inherit pkgs; }
, ghc ? "default"
}:

nix-hs {
  cabal = ./openid-connect.cabal;
  flags = [ "example" ];
  compiler = ghc;

  overrides = lib: self: super:
    with lib; {
      # Version 0.8 has an overly restrictive constraint on base:
      http-media = doJailbreak super.http-media;
    };
}
