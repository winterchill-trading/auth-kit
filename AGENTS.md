# auth-kit: agent guide

## Purpose

Account-security rules for consumer finance services: passcode strength rules, Argon2id hashing
in PHC strings, progressive lockout, a reset hook, device records, an append-only security log
with stable kinds, idle auto-lock and the account side of step-up confirmation. Everything is a
pure value or function; the service stores the records it gets back.

## Layout

| Path | Holds |
| --- | --- |
| `lib/` | Library `auth-kit` (module `Auth_kit`): `Passcode_policy`, `Phc`, `Password_hash`, `Lockout`, `Passcode`, `Device`, `Security_log`, `Auto_lock`, `Step_up_policy`. Depends on `core` only |
| `hash/` | Library `auth-kit.hash` (module `Auth_kit_hash`): Argon2id C stub over libargon2, PBKDF2-HMAC-SHA256, the default hasher |
| `bin/` | The `auth-kit` CLI: `hash`, `verify`, `inspect`, `bench`, `check-passcode` |
| `examples/` | `quick_start.ml`, run by CI |
| `test/` | Expect tests, Quickcheck properties, RFC vectors, the CLI cram test |
| `.github/` | CI workflow |

## Build, test, docs

libargon2 must be installed (`brew install argon2`, or `apt-get install libargon2-dev`); the
`hash/` library finds it through pkg-config. Run from this repository, inside the workspace:

    opam exec --switch 5.2.0+ox -- dune build --root .. @auth-kit/all
    opam exec --switch 5.2.0+ox -- dune build --root .. @auth-kit/runtest
    opam exec --switch 5.2.0+ox -- dune build --root .. @auth-kit/doc

Several agents building at once need `DUNE_BUILD_DIR=_build-auth-kit`. A workspace build can
exit 1 because of another repository's half-written files; judge by errors under `auth-kit/`.

Standalone: add the organization's opam repository
(`opam repo add winterchill https://github.com/winterchill-trading/opam-repository.git`), install
the dependencies (service-kit is a test dependency), then `dune build`.

## Conventions

- Format this repository only: `dune build --root .. @auth-kit/fmt --auto-promote`. Never
  `dune fmt` at the workspace root.
- Every module has an `.mli`; every public value has an odoc comment; the docs build is clean.
- Persisted records (`Lockout`, `Passcode`, `Password_hash`, `Device`, `Security_log` kinds and
  entries, `Auto_lock`) are `Stable.V1` with digests pinned in tests. Security-log wire names are
  append-only: never rename or remove a kind.
- Functions take `~now`; nothing reads the clock. Times in sexps are UTC
  (`Time_ns.Stable.Alternate_sexp.V1`).
- Operations return the record to store, the result and the events; keep that shape so a
  failed attempt still updates the lockout.
- Tests use tiny Argon2id costs (`memory_kib = 8`); never lower `Argon2id.default`.
- Comments for humans at non-obvious choices; `CHANGES.md` "Unreleased" for user-visible changes.

## Dependencies

- External: `core`, `ppx_jane`, `cryptokit`, `dune-configurator`, system libargon2.
- Tests: `async` and sibling `../service-kit` (step-up grants), pinned in CI.
- No sibling depends on auth-kit yet.

## CI

`.github/workflows/ci.yml` installs `libargon2-dev`, runs the `infra` ox-setup action with the
service-kit pin, then `dune build`, builds and runs the example, and `dune test`. The `obj-magic`
job calls the reusable workflow in `winterchill-trading/infra`. The odoc docs are checked locally
(`@auth-kit/doc`): installing odoc in CI is refused by the switch's `oxcaml-odoc` guard. Check a
run with `gh run list --limit 1` and at most one `gh run watch <id> --exit-status`.

## Pitfalls

- The C stub copies its inputs and releases the runtime lock; keep both if you touch it (a held
  lock stalls an Async scheduler for the whole hash).
- Stored hashes are untrusted: `Password_hash.of_string` checks costs against `Limits`; do not
  add a path that derives before that check.
- Inside `Time_ns.( ... )`, `now` means `Time_ns.now`; write `Time_ns.( > ) until now`.
- Lock lengths double step by step up to the cap; `scale_int span (1 lsl n)` overflows.
- Hash output is salted at random: expect tests print schemes and results, never hashes.
- Async expect tests live in their own file (`test_step_up_policy.ml`).

## Where to read more

- `README.md` (modules, hashing choices, known gaps)
- `../specs/repos/auth-kit.md` when present
- `../oxcaml-claude-skills/AGENTS.md` and `../oxcaml-claude-skills/GOTCHAS.md`
- Skills in `../oxcaml-claude-skills/skills/`: `banking-standards`, `janestreet-ocaml-style`

## Never do

- Run `opam install`, `upgrade` or `pin` that would change `ocaml-variants`, `core`, `base`,
  `async` or `ppx_jane` on the shared `5.2.0+ox` switch.
- Publish, tag or release.
- Log, print or commit secrets, passcodes or real hashes.
- Poll CI in a loop.
