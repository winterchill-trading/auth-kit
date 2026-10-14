# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- `Passcode_policy`: length, digits-only, repeated-digit, straight-run and deny-list rules.
- `Phc`: PHC string parsing and printing with canonical unpadded base64.
- `Password_hash`: scheme-tagged Argon2id and PBKDF2-SHA256 hashes, constant-time
  verification, rehash detection, limits on stored costs, a reader for hex PBKDF2 hashes.
- `Lockout`: five free attempts, then locks doubling from 1 minute to 1 hour.
- `Passcode`: set, verify, change, remove and reset over a stored record, returning
  security events.
- `Device`: device records with address prefixes, throttled last-seen and sign-out.
- `Security_log`: append-only entries with stable kinds, detail maps and notices.
- `Auto_lock`: idle lock settings that require a passcode.
- `Step_up_policy`: step-up requirements and grant issuing behind the passcode lockout.
- `auth-kit.hash`: Argon2id through libargon2 (runtime lock released), PBKDF2-HMAC-SHA256,
  and the default hasher.
- `auth-kit` CLI: `hash`, `verify`, `inspect`, `bench`, `check-passcode`.
