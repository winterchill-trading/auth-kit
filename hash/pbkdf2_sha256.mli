(** PBKDF2 with HMAC-SHA256 (RFC 8018), for verifying hashes stored before Argon2id. *)

open! Core

(** [derive ~iterations ~length ~salt ~password] is the [length]-byte derived key. Raises
    if [iterations < 1] or [length < 1]. *)
val derive : iterations:int -> length:int -> salt:string -> password:string -> string
