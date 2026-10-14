open! Core

module Config = struct
  type t =
    { free_attempts : int
    ; first_lock : Time_ns.Span.t
    ; max_lock : Time_ns.Span.t
    }
  [@@deriving sexp, compare, equal]

  let create ~free_attempts ~first_lock ~max_lock =
    if free_attempts < 1 then raise_s [%message "Lockout.Config: free_attempts < 1"];
    if Time_ns.Span.(first_lock <= zero)
    then raise_s [%message "Lockout.Config: first_lock must be positive"];
    if Time_ns.Span.(max_lock < first_lock)
    then raise_s [%message "Lockout.Config: max_lock < first_lock"];
    { free_attempts; first_lock; max_lock }
  ;;

  let default =
    create ~free_attempts:5 ~first_lock:Time_ns.Span.minute ~max_lock:Time_ns.Span.hour
  ;;
end

module Stable = struct
  module V1 = struct
    type t =
      { failures : int
      ; locked_until : Time_ns.Stable.Alternate_sexp.V1.t option
      }
    [@@deriving bin_io, sexp, compare, equal]

    let t_of_sexp sexp =
      let t = t_of_sexp sexp in
      if t.failures < 0 then of_sexp_error "Lockout: negative failures" sexp;
      t
    ;;
  end
end

type t = Stable.V1.t =
  { failures : int
  ; locked_until : Time_ns.t option
  }
[@@deriving compare, equal]

let sexp_of_t = Stable.V1.sexp_of_t
let initial = { failures = 0; locked_until = None }

module Status = struct
  type t =
    | Open of { attempts_left : int }
    | Locked of
        { until : Time_ns.t
        ; retry_after : Time_ns.Span.t
        }
  [@@deriving compare, equal]

  let sexp_of_t = function
    | Open { attempts_left } -> [%message "Open" (attempts_left : int)]
    | Locked { until; retry_after } ->
      [%message
        "Locked"
          (until : Time_ns.Stable.Alternate_sexp.V1.t)
          (retry_after : Time_ns.Span.t)]
  ;;
end

(* Doubles step by step and stops at the cap, rather than computing [first_lock * 2 ** n]:
   a long-lived counter (hundreds of wrong attempts over a week) would overflow the
   multiplication long before the cap applies. *)
let lock_for (c : Config.t) ~failures =
  if failures < c.free_attempts
  then None
  else (
    let rec double span k =
      if k = 0 || Time_ns.Span.(span >= c.max_lock)
      then Time_ns.Span.min span c.max_lock
      else double (Time_ns.Span.scale_int span 2) (k - 1)
    in
    Some (double c.first_lock (failures - c.free_attempts)))
;;

let status (c : Config.t) t ~now : Status.t =
  match t.locked_until with
  | Some until when Time_ns.( > ) until now ->
    Locked { until; retry_after = Time_ns.diff until now }
  | _ -> Open { attempts_left = Int.max 1 (c.free_attempts - t.failures) }
;;

let record_failure c t ~now =
  match status c t ~now with
  | Locked _ as s -> t, s
  | Open _ ->
    let failures = t.failures + 1 in
    let locked_until =
      match lock_for c ~failures with
      | None -> t.locked_until
      | Some span -> Some (Time_ns.add now span)
    in
    let t = { failures; locked_until } in
    t, status c t ~now
;;

let record_success _ = initial
let reset _ = initial
