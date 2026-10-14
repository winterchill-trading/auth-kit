(** Progressive lockout after wrong attempts.

    A short numeric secret can be guessed if attempts are free, so wrong attempts are
    counted. The first [free_attempts - 1] wrong attempts in a row cost nothing; the next
    one locks the secret for [first_lock], and every further wrong attempt after a lock
    has run out locks it again for twice as long as the previous lock, up to [max_lock]. A
    correct attempt (or a reset through another channel) clears the count.

    With {!Config.default} (5 attempts, 1 minute, 1 hour): wrong attempts 1-4 are free,
    the 5th locks for 1 minute, the 6th for 2, then 4, 8, 16, 32 and 60 minutes, and 60
    minutes for every wrong attempt after that.

    While locked, attempts must be refused {e without} checking the secret, and are not
    counted: {!record_failure} on a locked state changes nothing. The state is a small
    value the service stores next to the secret's hash; every function is pure and takes
    the current time explicitly. *)

open! Core

module Config : sig
  type t =
    { free_attempts : int (** wrong attempts up to and including the one that locks *)
    ; first_lock : Time_ns.Span.t
    ; max_lock : Time_ns.Span.t
    }
  [@@deriving sexp, compare, equal]

  (** 5 attempts, a first lock of 1 minute, doubling up to 1 hour. *)
  val default : t

  (** Raises unless [free_attempts >= 1] and [0 < first_lock <= max_lock]. *)
  val create
    :  free_attempts:int
    -> first_lock:Time_ns.Span.t
    -> max_lock:Time_ns.Span.t
    -> t
end

type t = private
  { failures : int (** wrong attempts since the last success or reset *)
  ; locked_until : Time_ns.t option
  (** set by the attempt that locked; may lie in the past *)
  }
[@@deriving sexp_of, compare, equal]

(** No failures, not locked. *)
val initial : t

module Status : sig
  type t =
    | Open of { attempts_left : int }
    (** Attempts are accepted. [attempts_left] is how many wrong attempts remain before
        the secret locks, counting the one that locks: 1 means the next wrong attempt
        locks. Always at least 1. *)
    | Locked of
        { until : Time_ns.t
        ; retry_after : Time_ns.Span.t (** [until - now], positive *)
        }
  [@@deriving sexp_of, compare, equal]
end

(** Whether an attempt may be made at [now]. *)
val status : Config.t -> t -> now:Time_ns.t -> Status.t

(** How long the [n]th wrong attempt in a row locks for, or [None] while [n] is below
    [free_attempts]. Never longer than [max_lock]. *)
val lock_for : Config.t -> failures:int -> Time_ns.Span.t option

(** A wrong attempt at [now]: the new state and the status after it. A no-op while locked
    (the attempt should not have been checked). *)
val record_failure : Config.t -> t -> now:Time_ns.t -> t * Status.t

(** A correct attempt: back to {!initial}. *)
val record_success : t -> t

(** The secret was reset through another channel (for example a one-time code sent to the
    customer's address): back to {!initial}. *)
val reset : t -> t

module Stable : sig
  module V1 : sig
    type nonrec t = t [@@deriving bin_io, sexp, compare, equal]
  end
end
