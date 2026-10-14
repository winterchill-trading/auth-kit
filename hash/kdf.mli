(** The derivation and randomness behind {!Auth_kit.Password_hash.Hasher}.

    {[
      let hasher = Auth_kit_hash.Kdf.hasher () in
      let stored = Auth_kit.Password_hash.Hasher.hash hasher "120587" |> ok_exn in
      Auth_kit.Password_hash.verify hasher stored "120587"
    ]} *)

open! Core

(** Derives under either scheme. *)
val derive
  :  Auth_kit.Password_hash.Scheme.t
  -> salt:string
  -> secret:string
  -> string Or_error.t

(** [n] bytes from the operating system's secure random source. *)
val random : int -> string

(** A hasher over {!derive} and {!random}; new hashes use [target] (default
    {!Auth_kit.Password_hash.Argon2id.default}). *)
val hasher
  :  ?limits:Auth_kit.Password_hash.Limits.t
  -> ?target:Auth_kit.Password_hash.Scheme.t
  -> unit
  -> Auth_kit.Password_hash.Hasher.t
