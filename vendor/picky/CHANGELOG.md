# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[7.0.0-rc.26](https://github.com/Devolutions/picky-rs/compare/picky-v7.0.0-rc.25...picky-v7.0.0-rc.26)] - 2026-07-21

### <!-- 7 -->Build

- Move RustCrypto crates to stable releases and drop obsolete pins ([#512](https://github.com/Devolutions/picky-rs/issues/512)) ([74090c9d1a](https://github.com/Devolutions/picky-rs/commit/74090c9d1ae301c8d46ed04f593acbfb3f5108e8)) 

  Several release-candidate crypto dependencies now have stable releases
  and are moved off their `=x.y.z-rc.n` pins.



## [[7.0.0-rc.25](https://github.com/Devolutions/picky-rs/compare/picky-v7.0.0-rc.24...picky-v7.0.0-rc.25)] - 2026-06-26

### <!-- 7 -->Build

- Align RustCrypto ECC dependency versions and remove unnecessary transitive pins ([#506](https://github.com/Devolutions/picky-rs/issues/506)) ([a4346f2853](https://github.com/Devolutions/picky-rs/commit/a4346f2853e726eb05b1fb5de2fa9351c8c44e2e)) 



## [[7.0.0-rc.24](https://github.com/Devolutions/picky-rs/compare/picky-v7.0.0-rc.23...picky-v7.0.0-rc.24)] - 2026-06-19

### <!-- 7 -->Build

- Bump sha3 from 0.11.0 to 0.12.0 ([#495](https://github.com/Devolutions/picky-rs/issues/495)) ([0b065a59fb](https://github.com/Devolutions/picky-rs/commit/0b065a59fb1e65c354084016166a7822ab10f7bf)) 

- Advance RustCrypto pins to the current rc.18/rc.33/rc.10 cluster ([#501](https://github.com/Devolutions/picky-rs/issues/501)) ([7d4b2675b9](https://github.com/Devolutions/picky-rs/commit/7d4b2675b91f7803905d972501130fc09d42ce1c)) 

## [[7.0.0-rc.23](https://github.com/Devolutions/picky-rs/compare/picky-v7.0.0-rc.22...picky-v7.0.0-rc.23)] - 2026-04-21

### <!-- 7 -->Build

- Upgrade RustCrypto dependencies ([#476](https://github.com/Devolutions/picky-rs/issues/476)) ([8ce838e347](https://github.com/Devolutions/picky-rs/commit/8ce838e3470ac605c912f61dc67c1c6d388b140d)) 

## [[7.0.0-rc.22](https://github.com/Devolutions/picky-rs/compare/picky-v7.0.0-rc.21...picky-v7.0.0-rc.22)] - 2026-02-27

### <!-- 4 -->Bug Fixes

- Bump `sha1` to v0.11.0-rc.3 ([#463](https://github.com/Devolutions/picky-rs/issues/463)) ([e40aee72bd](https://github.com/Devolutions/picky-rs/commit/e40aee72bd248bda84e6fe9e84a648784a6374ed)) 

## [[7.0.0-rc.21](https://github.com/Devolutions/picky-rs/compare/picky-v7.0.0-rc.20...picky-v7.0.0-rc.21)] - 2026-02-02

### <!-- 7 -->Build

- Update crypto dependencies ([#448](https://github.com/Devolutions/picky-rs/issues/448)) ([0bf42c1c4b](https://github.com/Devolutions/picky-rs/commit/0bf42c1c4bd727eaf5b4b0a877e8698986e0bd37)) 

- Remove transitive pem-rfc7468 crate ([#449](https://github.com/Devolutions/picky-rs/issues/449)) ([cc4caf455d](https://github.com/Devolutions/picky-rs/commit/cc4caf455defd38ef37fc15434b173275937d534)) 

- Bump reqwest from 0.12.24 to 0.13.1 ([#453](https://github.com/Devolutions/picky-rs/issues/453)) ([9cbaab9395](https://github.com/Devolutions/picky-rs/commit/9cbaab93955f2fef8f96a589b22e2582d4a8cbf0)) 

## [[7.0.0-rc.20](https://github.com/Devolutions/picky-rs/compare/picky-v7.0.0-rc.19...picky-v7.0.0-rc.20)] - 2025-11-07

### <!-- 4 -->Bug Fixes

- Pin leftover pre-release crypto crates ([#430](https://github.com/Devolutions/picky-rs/issues/430)) ([0fe43dae7b](https://github.com/Devolutions/picky-rs/commit/0fe43dae7b463a16d48b00b08ca6ce21a013af74)) 

  The patch version upgrade is not allowed to bring breaking changes, but
  this rule doesn't work for an `rc` version. So we should pin the `rc`
  versions, to not allow _cargo_ update to a new `rc` automatically.

## [[7.0.0-rc.19](https://github.com/Devolutions/picky-rs/compare/picky-v7.0.0-rc.18...picky-v7.0.0-rc.19)] - 2025-10-10

### <!-- 1 -->Features

- Support parsing certs with MLDSA public keys ([#411](https://github.com/Devolutions/picky-rs/issues/411)) ([abc63dde88](https://github.com/Devolutions/picky-rs/commit/abc63dde88360e35ef225cfd1c279958f47c3abc)) 

### <!-- 7 -->Build

- Pin RustCrypto release candidate crates ([#417](https://github.com/Devolutions/picky-rs/issues/417)) ([8a79282bbc](https://github.com/Devolutions/picky-rs/commit/8a79282bbc0dae9df222f16d261b7dd1f03cd66f)) 

## [[7.0.0-rc.18](https://github.com/Devolutions/picky-rs/compare/picky-v7.0.0-rc.17...picky-v7.0.0-rc.18)] - 2025-09-26

### <!-- 7 -->Build

- Bump the crypto group across 1 directory with 3 updates (#388) ([58d179a0c3](https://github.com/Devolutions/picky-rs/commit/58d179a0c39d701025a363c3f294912c2881a8f5)) 

## [[7.0.0-rc.17](https://github.com/Devolutions/picky-rs/compare/picky-v7.0.0-rc.16...picky-v7.0.0-rc.17)] - 2025-08-18

### <!-- 7 -->Build

- Bump rstest from 0.25.0 to 0.26.1 (#391) ([2a169deba2](https://github.com/Devolutions/picky-rs/commit/2a169deba2ba177685d58550f4214f59f25ebec0)) 

## [[7.0.0-rc.16](https://github.com/Devolutions/picky-rs/compare/picky-v7.0.0-rc.15...picky-v7.0.0-rc.16)] - 2025-07-15

### <!-- 0 -->Security

- Reject issuer certificates missing basic constraints (#385) ([4d8be23912](https://github.com/Devolutions/picky-rs/commit/4d8be239126cd34843a74de017118823699b8aa7)) 

  As per RFC 5280:
  
  > The cA boolean indicates whether the certified public key may be used
  > to verify certificate signatures.  If the cA boolean is not asserted,
  > then the keyCertSign bit in the key usage extension MUST NOT be
  > asserted.  If the basic constraints extension is not present in a
  > version 3 certificate, or the extension is present but the cA boolean
  > is not asserted, then the certified public key MUST NOT be used to
  > verify certificate signatures.

## [[7.0.0-rc.15](https://github.com/Devolutions/picky-rs/compare/picky-v7.0.0-rc.14...picky-v7.0.0-rc.15)] - 2025-06-24

### <!-- 7 -->Build

- Bump MSVC to 1.85 (#379) ([302df9912d](https://github.com/Devolutions/picky-rs/commit/302df9912d6f038f21b64fc916bd82836944c382)) 

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[7.0.0-rc.14](https://github.com/Devolutions/picky-rs/compare/picky-v7.0.0-rc.13...picky-v7.0.0-rc.14)] - 2025-05-14

### <!-- 1 -->Features

- Add HttpSignature::to_signing_string() method ([fe054c47f0](https://github.com/Devolutions/picky-rs/commit/fe054c47f04920383d93371bda948a961cbefdfd)) 

  Equivalent to HttpSignature::to_string().

## [[7.0.0-rc.13](https://github.com/Devolutions/picky-rs/compare/picky-v7.0.0-rc.12...picky-v7.0.0-rc.13)] - 2025-03-03

### <!-- 4 -->Bug Fixes

- [**breaking**] Comply with draft-cavage-http-signatures-12 when signing HTTP messages (#351) ([f043d04e14](https://github.com/Devolutions/picky-rs/commit/f043d04e1462cf0eddd9140f22a4d364cb3ad9cd)) 

  Change request target handling to comply with draft-cavage-http-signatures-12 when signing HTTP messages.

## [[7.0.0-rc.12](https://github.com/Devolutions/picky-rs/compare/picky-v7.0.0-rc.11...picky-v7.0.0-rc.12)] - 2025-01-16

### <!-- 4 -->Bug Fixes

- Symlinks to license files in packages (#339) ([1834c04f39](https://github.com/Devolutions/picky-rs/commit/1834c04f3930fb1bbf040deb6525b166e378b8aa)) 

  Use symlinks instead of copying files to avoid a “dirty” state during
  cargo publish and preserve VCS info. With #337 merged, CI handles
  publishing consistently, so developer environments no longer matter.


## [7.0.0-rc.1 to 7.0.0-rc.11](https://github.com/Devolutions/picky-rs/compare/picky-6.4.0...picky-v7.0.0-rc.11)

### Added

- Support for ECDSA p256 p384 and p521 signatures
- Support for MD5 hashing
- CTL implementation behind `ctl` feature
- CTL fetching over HTTP is behind `ctl_http_fetch` feature
- `Pkcs7::digest_algorithms`
- `Pkcs7::signer_infos`
- `Pkcs7::encapsulated_content_info`
- `Pkcs7::decode_certificates`
- `impl From<Pkcs7Certificate> for Pkcs7`
- `impl From<Pkcs7> for Pkcs7Certificate`
- `AuthenticodeSignature` struct
- `AuthenticodeSignature::new`
- `AuthenticodeSignature::from_der`
- `AuthenticodeSignature::from_pem`
- `AuthenticodeSignature::from_pem_str`
- `AuthenticodeSignature::to_der`
- `AuthenticodeSignature::to_pem`
- `AuthenticodeSignature::signing_certificate`
- `AuthenticodeSignature::authenticode_verifier`
- `AuthenticodeSignature::file_hash`
- `Authenticated_attributes::authenticated_attributes`
- `Authenticated_attributes::unauthenticated_attributes`
- `impl From<Pkcs7> for AuthenticodeSignature`
- `From<AuthenticodeSignature> for Pkcs7`
- Authenticode validation
- Support for `AuthenticodeSignature` timestamping:
  - Method `timestamp` to `AuthenticodeSignature`
  - `Timestamper` trait.
  - Timestamping implementation using reqwest is behind `http_timestamp` feature
- Authenticode timestamp request struct - `TimestampRequest`
- `AuthenticodeBuilder` for easier `AuthenticodeSignature` creation
- `SignatureAlgorithm::hash_algorithm`
- Support for `time 0.3` types conversions behind `time_conversion` feature gate
- `PrivateKey::to_pem_str`
- `PrivateKey::from_ec_components`
- `PrivateKey::from_ec_der_with_curve`
- `PrivateKey::from_ec_der_with_curve_oid`
- `PrivateKey::generate_ec`
- `PrivateKey::generate_ed`
- `PrivateKey::from_ec_encoded_components`
- `PrivateKey::from_ed_encoded_components`
- `PublicKey::to_pem_str`
- Support SSH keys and certificates
- `CheckedJwtEnc::new_with_cty`
- `CheckedJwtSig::new_with_cty`
- Support for JWT additional header parameters
- Support for EC private/public keys
- JWS and JWK EC curves support
- EC curves support for SSH keys and certificates
- EC x509 certificates verification/signing
- `JwkKeyType::new_ec_key`
- `JwkKeyType::new_ed_key`
- `JwkKeyType::as_ec`
- `JwkKeyType::as_ed`
- `JwkKeyType::is_ec`
- `JwkKeyType::is_ed`
- `SshPrivateKey::generate_ec`
- `SshPrivateKey::generate_ed`
- `JwkEcPublicKeyCurve` enum
- `JwkEdPublicKeyAlgorithm` enum
- `JwsAlg::EdDSA` variant
- `JwsAlg::ED25519` variant (`#[deprecated]` from the start, just for compatibility with other libs)
- Support for X25519 and Ed25519 public/private keys
- JWS and JWK Ed25519 keys/signing support
- Ed25519 support for SSH keys and certificates
- Ed25519 x509 certificates verification/signing
- Support for `ECDH-ES` JWE algorithm (P256, P384 and P521 EC keys, X25519 ED keys)
- Support for `PKCS12`(PFX) files parsing/building
- PuTTY PPK key format support

### Changed

- Bump minimal rustc version to 1.70
- Updated `p256`/`p384` to latest version
- (Breaking) Move Authenticode related code from `picky::x509::wincert` to `picky::x509::pkcs7::authenticode` module
- (Breaking) Authenticode implementation is now behind `pkcs7` feature
- (Breaking) `PrivateKey::to_pem` and `PublicKey::to_pem` now return a `Pem`
- (Breaking) Separate JWT validation from decoding in JOSE API (this makes API more convenient to first process header
    and then decide what kind of validation should be applied, or what claims type to deserialize into)
- (Breaking) `PrivateKey` now have private struct representation instead of open enum
- (Breaking) Now all `PrivateKey::to_public` and all related APIs for private keys return `Result`
  instead of plain `PublicKey`. This change was required because added support for EC/ED keys is not
  infallible in regard to public key extraction (public key could be missing from the file and could
  not be generated because of an unsupported algorithm/curve)
- "picky-test-data" is a new dev-dependency.

### Removed

- (Breaking) `ec` non-default cargo feature (EC operations now enabled by default)

### Fixed

- `BufReader` panic in `WinCertificate::decode` and `WinCertificate::encode` if data len is bigger than default capacity.
- `WinCertificate` encoding: `length` wasn’t correct.
- Leading zeros in JWK encoding.

  JWK encoding of a value is the unsigned big-endian representation as an octet sequence.
  The octet sequence MUST utilize the minimum number of octets needed to represent the value.
  That is: **no leading zero** must be present.

  See issue [#140](https://github.com/Devolutions/picky-rs/issues/140)

- Fetch curve info from private_key_algorithm ([#143](https://github.com/Devolutions/picky-rs/issues/143))

  Pick curve info from private_key_algorithm field.

- Missing `zeroize` on drop of internal `EcdsaKeypair` structure
- Fixed invalid padding logic of encrypted SSH keys
- Fixed invalid generated SSH EC keys

### Removed

- (Breaking) `Jwt::new_encrypted`
- (Breaking) `Jwt::new_signed`

## [6.4.0](https://github.com/Devolutions/picky-rs/compare/picky-6.3.0...picky-6.4.0) – 2021-08-10

### Changed

- Bump minimum supported Rust version to 1.51
- Update `rsa` dependency to `0.5`
- Update `picky-asn1` dependency to `0.4`
- More robust certification validation (see commit [f5f8cb60e41](https://github.com/Devolutions/picky-rs/commit/f5f8cb60e410ffe49aabace131f7b802e206ced0) for details)

## [6.3.0](https://github.com/Devolutions/picky-rs/compare/picky-6.2.0...picky-6.3.0) – 2021-05-27

### Added

- PKCS7 implementation behind `pkcs7` feature
- `WinCertificate` for authenticode behind `wincert` feature

### Changed

- Update `aes-gcm` dependency to `0.9`

## [6.2.0](https://github.com/Devolutions/picky-rs/compare/picky-6.1.1...picky-6.2.0) – 2021-03-04

### Added

- `Csr::generate_with_attributes` to generate CSR with attributes.
- `CertificateBuilder::inherit_extensions_from_csr_attributes` to allow certificate to inherit extensions requested by CSR attribute.
- Various API additions to `GeneralNames` for improved ergonomics.

## 6.1.2 – 2021-01-11

### Fixed

- Fix bad `use`s statements to `serde::export`

## 6.1.1 – 2020-12-11

### Fixed

- Fix `HttpSignatureError`'s Display trait implementation (`certificate expired` → `signature expired`).
- Fix certificate validity period that MUST be encoded as `UTCTime` through the year 2049 as per RFC 5280.
  Previously, they were always encoded as `GeneralizedTime`.

## 6.1.0 – 2020-10-21

### Added

- `CertificateBuilder::serial_number` can be used to provide a custom serial number instead of generating one.

### Fixed

- Bad generation for second exponent (`pq`) when generating PKCS#8 structure.
- Serial number was sometimes generated as negative.

## 6.0.0 – 2020-10-13

### Added

- Implementation of `Jwe` (JSON Web Encryption) RFC.
- Email attribute can be added to `DirectoryName` using `add_email` method.
- `from_pem_str` method to `Cert`, `Csr`, `PrivateKey` and `PublicKey`.

### Changed

- Separate `SignatureHashType` into two separate enums `HashAlgorithm` and `SignatureAlgorithm`.
- `KeyIdGenError` is now wrapping a `HashAlgorithm`.
- Update `rsa` dependency.
- `HttpSignature` store custom `algorithm` names instead of just ignoring them.
- Major `jose` module changes
  - JOSE header fields are renamed to be identical to RFCs when possible.
  - `Jwt` is now divided into `Jws` (JSON Web Signature) and `Jwe` (JSON Web Encryption)
  - `Jws` provides an API to sign any kind of data (binary). JSON claims are part of `Jwt` only.
  - `Jwe` provides an API to encrypt any kind of data (binary). JSON claims are part of `Jwt` only.
- Typo in `CertificateBuilder` API: `valididy` has been renamed to `validity`.

### Fixed

- RSA private key generation ([#53](https://github.com/Devolutions/picky-rs/issues/53)).

## 5.1.1 – 2020-07-13

### Changed

- Better `CaChainError::AuthorityKeyIdMismatch` display.

## 5.1.0 – 2020-07-07

### Added

- Add `BufRead`-based API to read PEM streams: `pem::Pem::read_from` and `pem::read_pem`.

### Changed

- Some internal types are moved to a new `picky_asn1_x509` crate but API is unchanged.
- Dependencies clean up.

## 5.0.0 – 2020-05-06

### Added

- Add `into_public_key` method to `x509::Cert`.
- Support for the ["algorithm" http signature parameter](https://tools.ietf.org/html/draft-cavage-http-signatures-12#section-2.1.3).

### Changed

- `Jwt` has no generic lifetime parameter anymore.

### Removed

- `Cert::verify` and `Cert::verify_chain` methods (previously deprecated)
- `HttpRequest` trait impl for `http` crate v0.1

### Fixed

- Add missing parameters for AES and SHA object identifiers ([668c06e8d](https://github.com/Devolutions/picky-rs/commit/668c06e8d8e8a0caae8bd13cf81c189bbc2e4918))

## 4.7.0 – 2020-04-16

### Added

- Implement `From<UTCDate>` trait on `DateTime<Utc>`.
- Support for leeway in HTTP signature verifier.
- Verifier API to X509 Cert.

### Deprecated

- `Cert::verify` and `Cert::verify_chain` methods in favor of the `Cert::verifier` method.
