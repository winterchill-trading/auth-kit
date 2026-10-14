(** A customer's passcode: setting, checking, changing, removing and resetting it.

    The record ({!t}) is what a service stores per account: nothing, or the passcode's
    {!Password_hash.t}, when it was set and its {!Lockout.t} counter. Every operation is a
    pure function from the stored record and the customer's input to an {!outcome}: the
    record to store next, the result, and the {!Security_log.Kind.t}s to append.

    Store [outcome.record] whenever it differs from the record passed in,
    {e including when the result is an error}: a wrong passcode changes the lockout
    counter, and a correct one checked against an outdated hash scheme brings a fresh
    hash.

    Hashing costs time on purpose (15-20 ms at the default Argon2id costs). The functions
    here call the hasher synchronously; an Async service runs them under [In_thread.run]
    (the [auth-kit.hash] binding releases the runtime lock).

    {[
      let config = Passcode.Config.default in
      let { Passcode.record; result; events } =
        Passcode.verify config ~hasher stored ~passcode:"120587" ~now
      in
      (* store [record], append [events], then act on [result] *)
    ]} *)

open! Core

module Config : sig
  type t =
    { policy : Passcode_policy.t
    ; lockout : Lockout.Config.t
    ; reset_proof_max_age : Time_ns.Span.t
    (** how long after the out-of-band code was accepted a reset may still use it *)
    }
  [@@deriving sexp, compare, equal]

  (** Six digits ({!Passcode_policy.six_digits}), {!Lockout.Config.default}, and reset
      proofs valid for 10 minutes. *)
  val default : t
end

type t =
  | Not_set
  | Set of
      { hash : Password_hash.t
      ; set_at : Time_ns.t
      ; lockout : Lockout.t
      }
[@@deriving sexp_of, compare, equal]

module Status : sig
  type t =
    | Not_set
    | Set of { set_at : Time_ns.t }
    | Locked of
        { set_at : Time_ns.t
        ; until : Time_ns.t
        ; retry_after : Time_ns.Span.t
        }
  [@@deriving sexp_of, compare, equal]
end

(** The record's state at [now], as an account settings screen shows it. *)
val status : Config.t -> t -> now:Time_ns.t -> Status.t

(** Whether a passcode is set (locked or not). Services typically ask for step-up
    confirmation and offer an idle auto-lock only while this holds. *)
val is_set : t -> bool

module Error : sig
  type t =
    | Weak of Passcode_policy.Violation.t (** the new passcode breaks a rule *)
    | Already_set (** use {!change} *)
    | Not_set
    | Wrong of { attempts_left : int } (** see {!Lockout.Status.Open} *)
    | Locked of
        { until : Time_ns.t
        ; retry_after : Time_ns.Span.t
        }
    (** Locked before the attempt (the passcode was not checked), or by this wrong
        attempt. *)
    | Stale_reset_proof (** the out-of-band code was accepted too long ago *)
    | Hash_failed of Core.Error.t (** the key derivation failed; log it *)
  [@@deriving sexp_of]

  (** A stable snake_case code: [weak], [already_set], [not_set], [wrong], [locked],
      [stale_reset_proof] or [hash_failed]. *)
  val code : t -> string
end

type 'a outcome =
  { record : t (** store this *)
  ; result : ('a, Error.t) Result.t
  ; events : Security_log.Kind.t list (** append these, in order *)
  }
[@@deriving sexp_of]

(** Sets a first passcode. [Already_set] if there is one; [Weak] if it breaks the policy.
    Records [passcode_set]. *)
val set
  :  Config.t
  -> hasher:Password_hash.Hasher.t
  -> t
  -> passcode:string
  -> now:Time_ns.t
  -> unit outcome

(** Checks a passcode, counting wrong attempts. While locked the passcode is not checked
    and nothing changes. A wrong attempt that locks records [passcode_locked]; a correct
    one clears the counter (and rehashes under the hasher's target scheme when the stored
    hash is outdated). Records nothing else: callers checking for a step-up add their own
    event on failure. *)
val verify
  :  Config.t
  -> hasher:Password_hash.Hasher.t
  -> t
  -> passcode:string
  -> now:Time_ns.t
  -> unit outcome

(** Replaces the passcode after checking the current one. The new passcode is checked
    against the policy first, so a typo in it does not cost an attempt. Records
    [passcode_changed]. *)
val change
  :  Config.t
  -> hasher:Password_hash.Hasher.t
  -> t
  -> current:string
  -> new_passcode:string
  -> now:Time_ns.t
  -> unit outcome

(** Removes the passcode after checking it. Records [passcode_removed]. Whatever depends
    on a passcode (passkeys enrolled as an alternative to it, {!Auto_lock}) is the
    caller's to remove as well. *)
val remove
  :  Config.t
  -> hasher:Password_hash.Hasher.t
  -> t
  -> passcode:string
  -> now:Time_ns.t
  -> unit outcome

(** Proof that the customer just passed an out-of-band check for a passcode reset, usually
    a one-time code sent to their verified address.

    This module does not send or check codes; the service builds a proof only after its
    code verifier accepted a code issued {e for passcode reset} (a sign-in code must not
    reset a passcode). *)
module Reset_proof : sig
  type t [@@deriving sexp_of]

  (** [challenge_id] identifies the accepted code, for the audit trail. *)
  val of_verified_code : challenge_id:string -> verified_at:Time_ns.t -> t

  (** The accepted code's challenge id. *)
  val challenge_id : t -> string

  (** When the code was accepted. *)
  val verified_at : t -> Time_ns.t
end

(** Sets a new passcode without the old one, given a fresh {!Reset_proof.t}. Clears any
    lockout. [Not_set] when there is no passcode to reset. Records [passcode_reset]. *)
val reset
  :  Config.t
  -> hasher:Password_hash.Hasher.t
  -> t
  -> proof:Reset_proof.t
  -> new_passcode:string
  -> now:Time_ns.t
  -> unit outcome

module Stable : sig
  module V1 : sig
    type nonrec t = t [@@deriving bin_io, sexp, compare, equal]
  end
end
