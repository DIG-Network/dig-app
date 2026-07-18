# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.4.0] - Unreleased

### Added

- **Profiles (U5, multi-DID).** The `profiles` module implements multi-profile identity management:
  create (provision a `did:chia:` DID + keys, then seal the profile's initial data), select the
  active profile, list profiles, and edit persona metadata. Each profile's secret-bearing state is
  DIGOP1-sealed at rest under its own per-profile DEK in its own AppData directory, so profiles are
  cryptographically isolated (NC-2/NC-3). Profile metadata maps onto the canonical `dig-identity`
  (#771) sparse-merkle-tree of standard slots — the format is consumed, never reinvented.
- **Real U4 sealing wired in.** The production `ProfileSealer` is `KeystoreSealer`: it seals each
  profile's blobs with U4's DIGOP1 under a DEK HKDF-derived from that profile's own identity key, so
  cross-profile isolation holds by the cipher (profile A's blob is undecryptable with profile B's
  DEK). The production `ProfileProvisioner` is `KeygenProvisioner` (U4 key generation + a
  wallet/engine `DidMinter` seam for the on-chain DID mint).
- **Crash-safe registry writes.** The plaintext profile registry — the only pointer to every
  profile's directory — is now written atomically and durably (temp file + fsync + rename), so a
  crash mid-save can never strand a profile's sealed data.
