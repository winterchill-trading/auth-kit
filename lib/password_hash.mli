(** Stored password and passcode hashes, tagged with their scheme.

    A stored hash records how it was made: the algorithm and its cost parameters, the salt
    and the derived bytes, in a {!Phc} string. Verification reads the scheme from the
    stored value, so a service can raise its costs (or move to another algorithm) at any
    time: old hashes still verify, and {!verify} answers [Match_rehash] when a correct
    secret was checked against an outdated scheme, which is the moment to store a fresh
    hash (the plain secret is only available then).

    Schemes:
    - {b Argon2id} (RFC 9106), version 0x13, the default for new hashes. The default
      parameters, 19 MiB of memory, 2 passes, 1 lane, are the minimum the OWASP password
      storage guidance recommends; one hash takes about 15-20 ms on a current laptop core.
    - {b PBKDF2-HMAC-SHA256} (RFC 8018), verify-only in practice: for hashes stored before
      Argon2id was available, which are upgraded on the next correct entry. Both the PHC
      form [$pbkdf2-sha256$i=N$salt$hash] and the hex form
      [pbkdf2-sha256$N$<salt hex>$<hash hex>] are read.

    This module does no cryptography itself: a {!Hasher.t} supplies the key derivation and
    the random source (the [auth-kit.hash] library builds one over libargon2 and
    cryptokit), so the parsing and policy code stays pure. *)

open! Core

module Argon2id : sig
  type t =
    { memory_kib : int (** m, in KiB; at least [8 * parallelism] *)
    ; iterations : int (** t, passes over memory *)
    ; parallelism : int (** p, lanes *)
    ; salt_length : int (** bytes *)
    ; hash_length : int (** bytes *)
    }
  [@@deriving sexp, compare, equal]

  (** m = 19456 KiB, t = 2, p = 1, 16-byte salt, 32-byte hash. *)
  val default : t
end

module Pbkdf2_sha256 : sig
  type t =
    { iterations : int
    ; salt_length : int
    ; hash_length : int
    }
  [@@deriving sexp, compare, equal]
end

module Scheme : sig
  type t =
    | Argon2id of Argon2id.t
    | Pbkdf2_sha256 of Pbkdf2_sha256.t
  [@@deriving sexp, compare, equal]

  (** The scheme's PHC id: [argon2id] or [pbkdf2-sha256]. *)
  val id : t -> string
end

(** Upper bounds on the costs a stored hash may ask for. A hash read back from storage is
    untrusted input: a damaged or tampered row asking for 64 GiB of memory must be
    refused, not attempted. *)
module Limits : sig
  type t =
    { max_memory_kib : int
    ; max_iterations : int
    ; max_parallelism : int
    ; max_pbkdf2_iterations : int
    ; min_salt_length : int
    ; min_hash_length : int
    ; max_length : int (** for salts and hashes, in bytes *)
    }
  [@@deriving sexp, compare, equal]

  (** 1 GiB, 64 passes, 16 lanes, 10 million PBKDF2 iterations, salts of at least 8 bytes,
      hashes of at least 16, both at most 64. *)
  val default : t

  (** Whether a scheme is within the limits. *)
  val check : t -> Scheme.t -> unit Or_error.t
end

(** A parsed stored hash. *)
type t = private
  { scheme : Scheme.t (** lengths in the scheme match [salt] and [hash] *)
  ; salt : string
  ; hash : string
  }
[@@deriving sexp_of, compare, equal]

(** Reads the PHC form of either scheme, or the hex PBKDF2 form; refuses anything else,
    Argon2 versions other than 0x13, and costs beyond [limits] (default
    {!Limits.default}). *)
val of_string : ?limits:Limits.t -> string -> t Or_error.t

(** The PHC form. *)
val to_string : t -> string

(** The key derivation and randomness a service hashes with. *)
module Hasher : sig
  type hash := t
  type t

  (** [derive scheme ~salt ~secret] must return [hash_length] bytes for [scheme], and
      [random n] [n] bytes from a cryptographically secure source. [target] is the scheme
      for new hashes; raises if it is outside [limits]. *)
  val create
    :  ?limits:Limits.t
    -> target:Scheme.t
    -> derive:(Scheme.t -> salt:string -> secret:string -> string Or_error.t)
    -> random:(int -> string)
    -> unit
    -> t

  (** The scheme new hashes are made with. *)
  val target : t -> Scheme.t

  (** The limits stored hashes and targets are checked against. *)
  val limits : t -> Limits.t

  (** A copy hashing new secrets with another scheme. *)
  val with_target : t -> Scheme.t -> t

  (** Hashes [secret] under the target scheme with a fresh salt. *)
  val hash : t -> string -> hash Or_error.t
end

module Verification : sig
  type t =
    | Mismatch
    | Match (** correct, and stored under the hasher's target scheme *)
    | Match_rehash
    (** correct, but stored under another scheme or other costs: hash the secret again and
        store the result *)
  [@@deriving sexp, compare, equal, enumerate]

  (** [Match] or [Match_rehash]. *)
  val is_match : t -> bool
end

(** Derives [secret] under the stored hash's own scheme and compares in constant time (the
    time taken does not depend on where the bytes differ). An error means the derivation
    itself failed, not that the secret was wrong. *)
val verify : Hasher.t -> t -> string -> Verification.t Or_error.t

(** Whether a hash is stored under a scheme other than the hasher's target. *)
val needs_rehash : Hasher.t -> t -> bool

(** Byte-string equality whose running time depends only on the lengths. *)
val constant_time_equal : string -> string -> bool

module Stable : sig
  module V1 : sig
    (** Serialised as its PHC string; reading checks it against {!Limits.default}. *)
    type nonrec t = t [@@deriving bin_io, sexp, compare, equal]
  end
end
