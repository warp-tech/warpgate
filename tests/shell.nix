# Every host tool the e2e harness and the API-client generators shell out to,
# at versions that behave like CI's. Enter with `nix-shell` from this
# directory, then `poetry install` and `poetry run pytest ...` (see README.md).
{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  packages = with pkgs; [
    python3
    poetry
    just
    jdk17 # @openapitools/openapi-generator-cli (npm run openapi:*)
    openssh # the ssh client the SSH tests drive
    expect
    kubectl
    mariadb_106.client # `mysql` for the tests that speak MySQL *through* Warpgate; its --ssl is opportunistic
    postgresql # psql for the Postgres protocol tests
    freerdp # xfreerdp (3.x: xfreerdp3) for the native RDP tests
    xvfb-run # a virtual display for xfreerdp
  ];
}
