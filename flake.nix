{
  description = "wanikani-mcp development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      forEachSystem = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { inherit system; }));
    in {
      devShells = forEachSystem (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            # the ui:// views in ui/
            bun
            cargo
            clippy
            rustc
            rustfmt
            rust-analyzer
            gh
            # assets/render.sh
            resvg
          ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isDarwin [ pkgs.libiconv ];

          # The fonts the assets/*.svg sources use, for assets/render.sh.
          ASSET_FONT_DIRS = "${pkgs.ibm-plex}/share/fonts ${pkgs.fira-code}/share/fonts";
          RUST_LOG = "wanikani_mcp=debug,tower_http=info";
          shellHook = ''
            echo "wanikani-mcp dev shell: bun $(bun --version), rust $(rustc --version | cut -d' ' -f2)"
          '';
        };
      });
    };
}
