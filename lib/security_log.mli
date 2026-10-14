(** An append-only log of security-relevant events on a customer's account.

    Customers expect to see when and where they signed in, when their passcode changed,
    when a device was signed out; support staff need the same history to answer "was this
    me?". Each entry has a stable kind with a wire name ([sign_in], [passcode_changed],
    ...) and a small detail map, so the log can be rendered by a client in any language
    without free text from the server.

    Kinds are only ever added, never renamed or removed: stored entries must stay
    readable. The digests of the stable types are pinned in the tests.

    The log here is an immutable value for tests and single-process tools; a service
    stores {!Entry.t} values itself and uses {!recent} and {!notices} over what it reads
    back. *)

open! Core

module Kind : sig
  type t =
    | Sign_in of
        { new_device : bool (** no earlier sign-in from this device *)
        ; new_user : bool (** the account was created by this sign-in *)
        }
    | Sign_out
    | Passcode_set
    | Passcode_changed
    | Passcode_reset (** set again after an out-of-band code, without the old one *)
    | Passcode_removed
    | Step_up_failed of { purpose : string }
    | Passcode_locked of { retry_after_seconds : int }
    | Biometric_enrolled (** a passkey or platform authenticator was registered *)
    | Biometric_removed
    | Device_signed_out of
        { device : string
        ; this_device : bool
        }
    | Other_devices_signed_out of { count : int }
    | Cards_frozen of { count : int }
    | Auto_lock_changed of { minutes : int option (** [None]: turned off *) }
  [@@deriving sexp, compare, equal]

  (** The stable snake_case wire name, for example [sign_in] or [auto_lock_changed]. *)
  val name : t -> string

  (** Every wire name, in declaration order. *)
  val all_names : string list

  module Detail : sig
    type t =
      | Bool of bool
      | Int of int
      | String of string
      | Null
    [@@deriving sexp, compare, equal]
  end

  (** The kind's fields as a flat map for clients, keys in lowerCamelCase as JSON APIs
      usually spell them ([newDevice], [retryAfterSeconds], ...). Empty for kinds without
      fields. *)
  val detail : t -> (string * Detail.t) list
end

module Entry : sig
  type t =
    { seq : int (** increases by one per entry in one account's log, from 1 *)
    ; at : Time_ns.t
    ; kind : Kind.t
    ; device : string option (** the device (session) the action came from *)
    ; user_agent : string option
    ; ip_prefix : string option (** see {!Device.Ip_prefix} *)
    }
  [@@deriving sexp_of, compare, equal]
end

(** One account's log, oldest entry first. *)
type t [@@deriving sexp_of]

(** A log with no entries. *)
val empty : t

(** Appends an entry with the next sequence number. Raises if [at] is earlier than the
    previous entry's time: the log is in time order. *)
val append
  :  t
  -> at:Time_ns.t
  -> ?device:string
  -> ?user_agent:string
  -> ?ip_prefix:string
  -> Kind.t
  -> t * Entry.t

(** Every entry, oldest first. *)
val entries : t -> Entry.t list

(** The number of entries. *)
val length : t -> int

(** The newest [limit] entries, newest first. Raises unless [1 <= limit <= 200]. *)
val recent : Entry.t list -> limit:int -> Entry.t list

(** Sign-ins from a new device other than [current_device] within [window] (default two
    days) before [now], newest first, at most [max] (default 10): the "was this you?"
    banner. *)
val notices
  :  ?window:Time_ns.Span.t
  -> ?max:int
  -> Entry.t list
  -> current_device:string option
  -> now:Time_ns.t
  -> Entry.t list

module Stable : sig
  module Kind : sig
    module V1 : sig
      type t = Kind.t [@@deriving bin_io, sexp, compare, equal]
    end
  end

  module Entry : sig
    module V1 : sig
      type t = Entry.t [@@deriving bin_io, sexp, compare, equal]
    end
  end
end
