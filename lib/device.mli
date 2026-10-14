(** The devices a customer is signed in on, as they see them in a "devices" list.

    One record per signed-in session: what the device said it was (user agent), roughly
    where it connected from (an address prefix, never the full address), when it signed
    in, when it was last active and when the session lapses. Customers can sign out any
    one device, or every device but the one in their hand.

    Records are values; the service stores them next to its sessions (the record id is the
    session's public id) and writes {!touch} results back when they change. *)

open! Core

(** A coarse network location kept instead of the full address: the first two octets of an
    IPv4 address ([203.0]) or the first three groups of an IPv6 address ([2001:db8:85a3]).
    Enough to tell "home" from "abroad" in a list, without storing personal data the
    service does not need. *)
module Ip_prefix : sig
  type t = private string [@@deriving sexp, compare, equal]

  (** Parses a textual IPv4 or IPv6 address (IPv4-mapped IPv6 counts as IPv4; a zone
      suffix [%eth0] is ignored) and keeps its prefix. [None] for anything else. *)
  val of_address : string -> t option

  val to_string : t -> string
end

type t =
  { id : string (** the session's public id *)
  ; user_agent : string option
  ; ip_prefix : Ip_prefix.t option
  ; signed_in_at : Time_ns.t
  ; last_active_at : Time_ns.t option (** [None] until the first {!touch} that writes *)
  ; expires_at : Time_ns.t
  ; signed_out_at : Time_ns.t option
  }
[@@deriving sexp_of, compare, equal]

(** A record for a sign-in at [now] lasting [lifetime]. The address, if given, is reduced
    to its prefix right away; user agents are cut to 512 bytes. *)
val create
  :  id:string
  -> ?user_agent:string
  -> ?ip_address:string
  -> now:Time_ns.t
  -> lifetime:Time_ns.Span.t
  -> unit
  -> t

(** Signed in, not signed out, and not expired at [now]. *)
val is_active : t -> now:Time_ns.t -> bool

(** Activity at [now]. [Some t'] when the stored record should be updated: the device was
    never marked active or was last marked at least [every] ago (5 minutes by default).
    [None] means no write is needed, which keeps a busy session from writing on every
    request. Inactive records are never touched. *)
val touch : ?every:Time_ns.Span.t -> t -> now:Time_ns.t -> t option

(** Signs the device out at [now]; a device already signed out keeps its first time. *)
val sign_out : t -> now:Time_ns.t -> t

(** What a devices screen shows. *)
module View : sig
  type device := t

  type t =
    { device : device
    ; current : bool (** the device making the request *)
    }
  [@@deriving sexp_of, compare, equal]
end

(** Active devices at [now], the current one first, then by latest activity (sign-in time
    when never touched), newest first. *)
val list : t list -> current:string -> now:Time_ns.t -> View.t list

(** Signs out device [id] if it is active and in [devices]. Returns the updated list and
    the security-log kind to record ([None] when nothing was signed out, which a service
    reports as "not found"). *)
val sign_out_one
  :  t list
  -> id:string
  -> current:string
  -> now:Time_ns.t
  -> t list * Security_log.Kind.t option

(** Signs out every active device except [current]. Returns the updated list, the count,
    and the kind to record (also recorded when the count is 0, so the customer sees their
    action). *)
val sign_out_others
  :  t list
  -> current:string
  -> now:Time_ns.t
  -> t list * int * Security_log.Kind.t

module Stable : sig
  module V1 : sig
    type nonrec t = t [@@deriving bin_io, sexp, compare, equal]
  end
end
