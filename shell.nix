with import (builtins.fetchTarball {
  # Commit hash source: https://nixos.org/channels/
  url = https://github.com/nixos/nixpkgs/archive/e7a327da5cffdf5e77e1924906a4f0983591bd3e.tar.gz;

  # Hash obtained using `nix-prefetch-url --unpack <url>`
  sha256 = "1xzil4mayhggg2miwspbk12nihlszg0y4n6i4qacrxql5n75f0hr";
}) { };

let
  hsPkgs = haskell.packages.ghc802;
in
  haskell.lib.buildStackProject {
     name = "cardano-sl";
     ghc = hsPkgs.ghc;
     buildInputs = [
       zlib openssh autoreconfHook openssl
       gmp rocksdb git bsdiff
       hsPkgs.happy hsPkgs.cpphs
     # cabal-install and stack pull in lots of dependencies on OSX so skip them
     # See https://github.com/NixOS/nixpkgs/issues/21200
     ] ++ (lib.optionals stdenv.isLinux [ cabal-install stack ])
       ++ (lib.optionals stdenv.isDarwin (with darwin.apple_sdk.frameworks; [ Cocoa CoreServices libcxx ]));
  }
