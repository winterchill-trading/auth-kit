# auth-kit

Account-security rules for consumer finance services, in OCaml: passcode strength
rules, Argon2id hashing in self-describing PHC strings, progressive lockout, a reset
hook for out-of-band codes, device records, an append-only security log with stable
event kinds, idle auto-lock settings, and the account side of step-up confirmation.

Everything is a pure value or function; nothing is persisted. A service stores the
small records this library hands back (a passcode record, device records, log entries)
in its own database and passes them in again on the next request.

## Why separate

Every app that holds money asks for a short secret before it moves any, and every one
has to get the same details right: refuse `123456`, hash with a memory-hard function,
stop guessing without locking the customer out forever, let them reset through another
channel, show them where they are signed in and what changed on their account. These
rules have nothing to do with HTTP, databases or any one service, and they are
easy to get subtly wrong (a lockout that can be dodged with a second factor, a reset
that accepts a sign-in code, a hash scheme that cannot be upgraded), so they live in
one small library with properties and test vectors. The HTTP side (sessions, grant
tokens, idempotency) lives in [service-kit](https://github.com/winterchill-trading/service-kit);
auth-kit plugs into its step-up grants without depending on it.

## Modules

| Module | What it does |
|---|---|
| `Passcode_policy` | Length, digits only, no single repeated digit, no straight run up or down, deny list. Pure, `core` only, so a web client can share it. |
| `Password_hash` | Stored hashes tagged with their scheme (Argon2id or PBKDF2-SHA256) and costs, constant-time verification, `Match_rehash` when a correct secret was stored under outdated costs, limits on the costs a stored hash may ask for. |
| `Phc` | The PHC string format and its unpadded base64. |
| `Lockout` | Wrong attempts 1-4 free, the 5th locks for 1 minute, each further one doubles the lock up to 1 hour; locked attempts are not checked or counted. |
| `Passcode` | The per-account record (`Not_set` or the hash, when it was set, the lockout) and `set`, `verify`, `change`, `remove`, `reset`; each returns the record to store, the result and the security events to append. |
| `Device` | One record per signed-in session: user agent, address prefix (IPv4 two octets, IPv6 three groups), signed in, last active (written at most every 5 minutes), expiry; sign out one or all others. |
| `Security_log` | Stable event kinds with wire names and a detail map (`sign_in {newDevice, newUser}`, `passcode_locked {retryAfterSeconds}`, ...), append-only sequence, recent entries, "new sign-in elsewhere" notices. |
| `Auto_lock` | Idle lock after 1, 5, 15 or 30 minutes, only while a passcode is set. |
| `Step_up_policy` | Whether an action needs a step-up (only with a passcode set; optionally from an amount), and earning one with the passcode (same lockout, `step_up_failed` logged) or a factor verified elsewhere (refused while locked). |
| `Auth_kit_hash` (`auth-kit.hash`) | Argon2id through libargon2 (releases the OCaml runtime lock), PBKDF2-HMAC-SHA256 over cryptokit, and the default hasher. |

## Quick start

libargon2 is a system dependency of `auth-kit.hash`:

```sh
brew install argon2                 # macOS
sudo apt-get install libargon2-dev  # Debian, Ubuntu
dune build
dune exec ./examples/quick_start.exe
echo 120587 | dune exec auth-kit -- hash
dune exec auth-kit -- bench -m 19456 -t 2
```

```
set 123456             (Weak Straight_run)
set 120587             ok
verify 000001 (#1)     (Wrong (attempts_left 4))
...
verify 000001 (#5)     (Locked (until "2026-07-01 10:01:05Z") (retry_after 1m))
reset to 530912        ok
signed out 1 other device(s)
```

The `auth-kit` CLI reads secrets from stdin only: `hash`, `verify HASH` (exit 1 on a
mismatch), `inspect HASH`, `bench` and `check-passcode`.

## Usage

```ocaml
open! Core
open Auth_kit

let hasher = Auth_kit_hash.Kdf.hasher () (* Argon2id, 19 MiB, 2 passes *)
let config = Passcode.Config.default

(* POST /passcode/change, inside In_thread.run: hashing takes ~17 ms *)
let change ~stored ~current ~new_passcode ~now =
  let { Passcode.record; result; events } =
    Passcode.change config ~hasher stored ~current ~new_passcode ~now
  in
  (* store [record] even on error: wrong attempts are counted *)
  save record;
  List.iter events ~f:append_security_event;
  match result with
  | Ok () -> respond_ok ()
  | Error (Wrong { attempts_left }) -> respond_invalid ~attempts_left
  | Error (Locked { retry_after; _ }) -> respond_429 ~retry_after
  | Error (Weak v) when Passcode_policy.Violation.is_format v -> respond_bad_format ()
  | Error (Weak _) -> respond_too_simple ()
  | Error e -> respond_error (Passcode.Error.code e)
```

Step-up with service-kit's grants (any `unit -> 'grant` works as the issuer):

```ocaml
module Grants = Service_kit.Step_up.Make (Purpose) (Service_kit.Step_up.Memory_spent)

let step_up ~stored ~passcode ~session_id ~now =
  Step_up_policy.with_passcode config ~hasher stored ~passcode
    ~purpose:(Purpose.to_string Payment) ~now
    ~issue:(fun () -> Grants.issue grants ~session_id ~purpose:Payment)

(* Before a payment: ask for a grant only while the customer has a passcode. *)
let needs_grant ~stored ~amount =
  Step_up_policy.required ~passcode:stored
    (From_amount { threshold = 50_000 }) ~amount
```

`test/test_step_up_policy.ml` runs this end to end: a wrong passcode logs
`step_up_failed`, the right one issues a grant, the grant is consumed once and refused
for another session.

## Hashing choices

- **Argon2id by binding, not in OCaml.** `auth-kit.hash` calls the reference C
  implementation (libargon2, found through pkg-config) with its own small stub rather
  than the opam `argon2` package: the stub copies its inputs and releases the runtime
  lock during the derivation, so `In_thread.run` keeps an Async scheduler responsive.
  The cost is a system library on every machine that builds the package. Verified
  against the RFC 9106 section 5.3 vector (with secret and associated data) and the
  reference implementation's `password`/`somesalt` vector.
- **Default costs**: m = 19456 KiB, t = 2, p = 1, 16-byte salt, 32-byte hash (the OWASP
  minimum for Argon2id): about 17 ms per hash on an M-series laptop core, 98 ms at
  m = 64 MiB, t = 3.
- **Upgrades**: the scheme and costs are stored with every hash; `verify` answers
  `Match_rehash` when the stored costs differ from the hasher's target, and
  `Passcode.verify`/`change`/`remove` store a fresh hash on the next correct entry.
- **PBKDF2-HMAC-SHA256** verifies hashes made before Argon2id was available, in the PHC
  form and in the hex form `pbkdf2-sha256$<iterations>$<salt hex>$<hash hex>` that
  services wrote before adopting PHC strings; they are rehashed with Argon2id on the
  next correct entry.
- **Untrusted stored values**: costs above `Limits.default` (1 GiB, 64 passes, 16 lanes,
  10 million PBKDF2 iterations) are refused when a stored hash is read, so a damaged
  row cannot make the server allocate gigabytes.

## Stable types

`Lockout`, `Passcode`, `Password_hash` (as its PHC string), `Device`, `Security_log`
kinds and entries, and `Auto_lock` have `Stable.V1` modules with bin_io and sexp; their
`[%bin_digest]`s are pinned in the tests, and times serialise in UTC. Security-log wire
names are listed in a test, so renaming one fails the build.

## Known gaps

- Binding a grant on first use to one request (operation plus idempotency key, or a
  card) is a grant-store concern and is not here; service-kit's `Step_up` currently
  consumes a grant once.
- The default hasher has no server-side secret key ("pepper"); `Argon2id.derive` takes
  one, but stored hashes do not record a key id yet.
- One-time codes for resets are produced and checked elsewhere; `Passcode.Reset_proof`
  only records that one was accepted, and when.

## Development

```sh
dune build @all @runtest
dune build @fmt --auto-promote
```

CI installs `libargon2-dev`, pins service-kit (used by the tests only), builds the
examples, runs the tests and the cram test of the CLI, and builds the docs with
warnings as errors.
