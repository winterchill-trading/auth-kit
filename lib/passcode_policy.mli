(** Strength rules for passcodes.

    A passcode is the short secret a customer types to unlock an app or confirm a payment.
    It is usually numeric and short, so the rules exist to refuse the guesses an attacker
    tries first: one digit repeated ([000000], [777777]) and straight runs up or down
    ([123456], [987654]). A deny list covers anything else a service wants to refuse
    (birth years, [121212], ...).

    {[
      match Passcode_policy.check Passcode_policy.six_digits "123456" with
      | Ok () -> ()
      | Error Straight_run -> (* ask for another one *) ()
      | Error _ -> ()
    ]}

    The rules are pure and depend on [core] only, so a web client can run the same checks
    before it sends anything. *)

open! Core

(** Why a passcode was refused. The first failing rule is reported, in the order the
    constructors are listed. *)
module Violation : sig
  type t =
    | Too_short (** fewer characters than [min_length] *)
    | Too_long (** more characters than [max_length] *)
    | Not_digits (** a character other than [0-9] when [digits_only] is set *)
    | All_same (** one character repeated over the whole passcode *)
    | Straight_run (** every digit one more, or every digit one less, than the previous *)
    | Denied (** on the policy's deny list *)
  [@@deriving sexp, compare, equal, enumerate]

  (** A stable snake_case name ([too_short], [straight_run], ...), for error codes. *)
  val to_string : t -> string

  (** Whether the passcode had the wrong shape ([Too_short], [Too_long], [Not_digits]) as
      opposed to the right shape but too easy to guess. Services usually report the two
      groups differently ("enter 6 digits" against "choose a less obvious passcode"). *)
  val is_format : t -> bool
end

type t =
  { min_length : int (** at least 1 *)
  ; max_length : int (** at least [min_length] *)
  ; digits_only : bool
  ; reject_all_same : bool
  ; reject_straight_runs : bool (** runs of digits only; no wrap-around (9 to 0) *)
  ; deny : String.Set.t (** exact matches refused *)
  }
[@@deriving sexp, compare, equal]

(** Exactly six digits, no repeated digit, no straight run, empty deny list. *)
val six_digits : t

(** A policy with the given length bounds and the same guess rules as {!six_digits}.
    Raises if [min_length < 1] or [max_length < min_length]. *)
val digits : min_length:int -> max_length:int -> t

(** [Ok ()] when [passcode] satisfies every rule, otherwise the first violation. *)
val check : t -> string -> (unit, Violation.t) Result.t

(** Every rule [passcode] breaks, in constructor order. Empty when {!check} succeeds. *)
val violations : t -> string -> Violation.t list
