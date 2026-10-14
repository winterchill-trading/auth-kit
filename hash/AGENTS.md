# hash: the `auth-kit.hash` library

Argon2id through libargon2 (`argon2_stubs.c`, flags from `config/discover.ml` via pkg-config),
PBKDF2-HMAC-SHA256 over cryptokit, and `Kdf.hasher`.

- The stub copies OCaml strings before `caml_enter_blocking_section`; never read OCaml values
  while the lock is released.
- `test/test_password_hash.ml` holds the RFC 9106 and RFC 7914 vectors; they must keep passing.
