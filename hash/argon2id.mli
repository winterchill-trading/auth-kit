(** Argon2id (RFC 9106, version 0x13) through the reference C implementation.

    The binding releases the OCaml runtime lock while it derives, so running it under
    [Async.In_thread.run] keeps the scheduler responsive. *)

open! Core

(** [derive ~secret_key ~associated_data costs ~salt ~password] is the raw tag of
    [costs.hash_length] bytes. [secret_key] (the RFC's K, a server-side "pepper") and
    [associated_data] (X) default to empty. Errors carry libargon2's message (salt shorter
    than 8 bytes, memory below [8 * parallelism], allocation failure, ...). *)
val derive
  :  ?secret_key:string
  -> ?associated_data:string
  -> Auth_kit.Password_hash.Argon2id.t
  -> salt:string
  -> password:string
  -> string Or_error.t
