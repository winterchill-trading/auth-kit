(** Idle auto-lock: the app locks itself after a period without interaction and asks for
    the passcode (or a passkey) again.

    The lock runs on the client, which knows when the customer last touched the screen;
    the server stores the setting and checks that it only exists while a passcode is set
    (there would be nothing to unlock with). Unlocking is a step-up for a purpose that
    authorises nothing else, so an unlock grant cannot move money.

    The functions are pure and need only [core], so a web client can share them. *)

open! Core

type t =
  | Off
  | After of { minutes : int }
[@@deriving sexp, compare, equal]

(** The idle periods customers may choose from, in minutes: 1, 5, 15 and 30. *)
val default_choices : int list

module Error : sig
  type t =
    | Passcode_required (** a period was chosen while no passcode is set *)
    | Not_a_choice of { minutes : int }
  [@@deriving sexp, compare, equal]

  (** [passcode_required] or [not_a_choice]. *)
  val code : t -> string
end

(** Changes the setting from [current] to [minutes] ([None] turns it off). Returns the new
    setting and the security-log kind to record, [None] when nothing changed. *)
val set
  :  ?choices:int list
  -> current:t
  -> passcode_set:bool
  -> minutes:int option
  -> unit
  -> (t * Security_log.Kind.t option, Error.t) Result.t

(** The setting after the passcode was removed: always [Off]. *)
val on_passcode_removed : t -> t

(** [After] minutes, or [None]. *)
val minutes : t -> int option

(** Whether the app should be locked at [now], given the last interaction. *)
val is_locked : t -> last_interaction:Time_ns.t -> now:Time_ns.t -> bool

module Stable : sig
  module V1 : sig
    type nonrec t = t [@@deriving bin_io, sexp, compare, equal]
  end
end
