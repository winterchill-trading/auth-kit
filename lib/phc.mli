(** PHC string format: the self-describing text form password hashes are stored in.

    {v $argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG v}

    The fields are the algorithm id, an optional version, comma-separated [name=value]
    parameters, the salt and the hash, the last two in standard base64 without padding
    (the PHC string format specification). Keeping the algorithm and its cost parameters
    in the stored value is what lets a service raise its costs or change algorithm later
    and still verify every hash it has stored. *)

open! Core

type t =
  { id : string (** [[a-z0-9-]], 1 to 32 characters *)
  ; version : int option (** the [v=] field, when present *)
  ; params : (string * string) list (** in the order written *)
  ; salt : string (** raw bytes *)
  ; hash : string (** raw bytes *)
  }
[@@deriving sexp_of, compare, equal]

(** Parses a PHC string. Every field up to the hash must be present; the salt and hash
    must be non-empty base64 without padding. *)
val of_string : string -> t Or_error.t

(** The PHC text form; [of_string (to_string t) = Ok t] for any [t] with a valid id and
    parameter names. *)
val to_string : t -> string

(** [param t name] is the value of parameter [name]. *)
val param : t -> string -> string option

(** Standard base64 (RFC 4648 section 4) without padding, as PHC strings use it. *)
module B64 : sig
  (** Encodes without padding. *)
  val encode : string -> string

  (** Refuses padding, characters outside the alphabet, a length of 1 modulo 4, and
      non-canonical trailing bits. *)
  val decode : string -> string Or_error.t
end
