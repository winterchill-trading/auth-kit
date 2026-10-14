# lib: the `auth-kit` library

Pure account-security rules over `core` only (no C, no Async), so a web client can share
`Passcode_policy` and `Auto_lock`. Hashing goes through `Password_hash.Hasher.t`, supplied by
`../hash`.

- Every operation takes `~now` and returns what to store plus security-log kinds.
- A new `Security_log.Kind` constructor needs a wire name in `name`, an entry in `all_names`,
  a `detail` case, and updated pinned digests in `test/`.
- Changing a `Stable.V1` type changes its pinned digest: add `V2` instead.
