(** When a step-up is needed, and how a customer earns one.

    A step-up grant is short-lived proof that the person holding a session re-entered
    their passcode (or used a passkey) for one specific action: a payment, revealing a
    card number, enrolling a new passkey. Issuing, binding and consuming grants is a
    session concern and lives with the session code (for example service-kit's
    [Step_up.Make]); this module holds the account side:

    - {b whether} an action needs a grant: only while a passcode is set (without one there
      is nothing to re-enter), and for some purposes only from an amount upwards;
    - {b earning} one: checking the passcode with the same lockout counter as every other
      passcode check, recording [step_up_failed] and [passcode_locked] in the security
      log, and calling the issuer only on success.

    {[
      Step_up_policy.with_passcode
        Passcode.Config.default
        ~hasher
        record
        ~passcode
        ~purpose:"payment"
        ~now
        ~issue:(fun () -> Grants.issue grants ~session_id ~purpose:Payment)
    ]} *)

open! Core

module Requirement : sig
  type t =
    | Always
    | From_amount of { threshold : int }
    (** Amounts of at least [threshold], in minor units of one reference currency. An
        amount that cannot be converted to it counts as above the threshold. *)
    | Never
  [@@deriving sexp, compare, equal]

  (** [amount] is in minor units of the reference currency, [None] when unknown; it is
      ignored by [Always] and [Never]. *)
  val applies : t -> amount:int option -> bool
end

(** Whether the action needs a grant: a passcode is set and the requirement applies. *)
val required : passcode:Passcode.t -> Requirement.t -> amount:int option -> bool

(** How the customer re-authenticated, as a grant records it. *)
module Method : sig
  type t =
    | Passcode
    | Passkey
  [@@deriving sexp, compare, equal, enumerate]

  (** [passcode] or [webauthn]. *)
  val to_string : t -> string
end

module Error : sig
  type t =
    | Passcode_not_set (** step-up is only offered while a passcode is set *)
    | Wrong of { attempts_left : int }
    | Locked of
        { until : Time_ns.t
        ; retry_after : Time_ns.Span.t
        }
    | Hash_failed of Core.Error.t
  [@@deriving sexp_of]

  (** [passcode_not_set], [wrong], [locked] or [hash_failed]. *)
  val code : t -> string
end

type 'grant outcome =
  { record : Passcode.t (** store this, as for {!Passcode.outcome} *)
  ; result : ('grant, Error.t) Result.t
  ; events : Security_log.Kind.t list
  }

(** Checks [passcode] for a step-up for [purpose] (its wire name, recorded in the log) and
    calls [issue] only if it is right. A wrong passcode records [step_up_failed], plus
    [passcode_locked] when it locks. *)
val with_passcode
  :  Passcode.Config.t
  -> hasher:Password_hash.Hasher.t
  -> Passcode.t
  -> passcode:string
  -> purpose:string
  -> now:Time_ns.t
  -> issue:(unit -> 'grant)
  -> 'grant outcome

(** For a factor verified elsewhere (a passkey assertion): calls [issue] unless the
    passcode is not set or is locked. A locked passcode blocks every step-up method, so a
    lockout cannot be sidestepped. [verified = false] records [step_up_failed] and issues
    nothing; it does not count towards the passcode lockout. *)
val with_verified_factor
  :  Passcode.Config.t
  -> Passcode.t
  -> verified:bool
  -> purpose:string
  -> now:Time_ns.t
  -> issue:(unit -> 'grant)
  -> ('grant, [ `Not_verified | `Error of Error.t ]) Result.t * Security_log.Kind.t list
