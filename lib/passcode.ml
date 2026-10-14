open! Core

module Config = struct
  type t =
    { policy : Passcode_policy.t
    ; lockout : Lockout.Config.t
    ; reset_proof_max_age : Time_ns.Span.t
    }
  [@@deriving sexp, compare, equal]

  let default =
    { policy = Passcode_policy.six_digits
    ; lockout = Lockout.Config.default
    ; reset_proof_max_age = Time_ns.Span.of_int_min 10
    }
  ;;
end

module Stable = struct
  module V1 = struct
    type t =
      | Not_set
      | Set of
          { hash : Password_hash.Stable.V1.t
          ; set_at : Time_ns.Stable.Alternate_sexp.V1.t
          ; lockout : Lockout.Stable.V1.t
          }
    [@@deriving bin_io, sexp, compare, equal]
  end
end

type t = Stable.V1.t =
  | Not_set
  | Set of
      { hash : Password_hash.t
      ; set_at : Time_ns.t
      ; lockout : Lockout.t
      }
[@@deriving compare, equal]

let sexp_of_t = Stable.V1.sexp_of_t

module Status = struct
  type t =
    | Not_set
    | Set of { set_at : Time_ns.Stable.Alternate_sexp.V1.t }
    | Locked of
        { set_at : Time_ns.Stable.Alternate_sexp.V1.t
        ; until : Time_ns.Stable.Alternate_sexp.V1.t
        ; retry_after : Time_ns.Span.t
        }
  [@@deriving sexp_of, compare, equal]
end

let status (config : Config.t) (t : t) ~now : Status.t =
  match t with
  | Not_set -> Not_set
  | Set { set_at; lockout; _ } ->
    (match Lockout.status config.lockout lockout ~now with
     | Open _ -> Set { set_at }
     | Locked { until; retry_after } -> Locked { set_at; until; retry_after })
;;

let is_set = function
  | Not_set -> false
  | Set _ -> true
;;

module Error = struct
  type t =
    | Weak of Passcode_policy.Violation.t
    | Already_set
    | Not_set
    | Wrong of { attempts_left : int }
    | Locked of
        { until : Time_ns.Stable.Alternate_sexp.V1.t
        ; retry_after : Time_ns.Span.t
        }
    | Stale_reset_proof
    | Hash_failed of Core.Error.t
  [@@deriving sexp_of]

  let code = function
    | Weak _ -> "weak"
    | Already_set -> "already_set"
    | Not_set -> "not_set"
    | Wrong _ -> "wrong"
    | Locked _ -> "locked"
    | Stale_reset_proof -> "stale_reset_proof"
    | Hash_failed _ -> "hash_failed"
  ;;
end

type 'a outcome =
  { record : t
  ; result : ('a, Error.t) Result.t
  ; events : Security_log.Kind.t list
  }
[@@deriving sexp_of]

let fail record error = { record; result = Error error; events = [] }

let new_hash (config : Config.t) ~hasher passcode =
  match Passcode_policy.check config.policy passcode with
  | Error v -> Error (Error.Weak v)
  | Ok () ->
    Password_hash.Hasher.hash hasher passcode
    |> Result.map_error ~f:(fun e -> Error.Hash_failed e)
;;

let set config ~hasher t ~passcode ~now =
  match t with
  | Set _ -> fail t Already_set
  | Not_set ->
    (match new_hash config ~hasher passcode with
     | Error e -> fail t e
     | Ok hash ->
       { record = Set { hash; set_at = now; lockout = Lockout.initial }
       ; result = Ok ()
       ; events = [ Passcode_set ]
       })
;;

let seconds_ceil span = Float.iround_up_exn (Time_ns.Span.to_sec span)

(* Shared by verify, change and remove: [on_success] gets the record with the lockout
   cleared (and the hash refreshed when its scheme is outdated). *)
let check (config : Config.t) ~hasher t ~passcode ~now ~on_success =
  match t with
  | Not_set -> fail t Not_set
  | Set ({ hash; lockout; _ } as s) ->
    (match Lockout.status config.lockout lockout ~now with
     | Locked { until; retry_after } -> fail t (Locked { until; retry_after })
     | Open _ ->
       (match Password_hash.verify hasher hash passcode with
        | Error e -> fail t (Hash_failed e)
        | Ok Mismatch ->
          let lockout, after = Lockout.record_failure config.lockout lockout ~now in
          let record = Set { s with lockout } in
          (match after with
           | Open { attempts_left } ->
             { record; result = Error (Wrong { attempts_left }); events = [] }
           | Locked { until; retry_after } ->
             { record
             ; result = Error (Locked { until; retry_after })
             ; events =
                 [ Passcode_locked { retry_after_seconds = seconds_ceil retry_after } ]
             })
        | Ok ((Match | Match_rehash) as m) ->
          let hash =
            match m with
            | Match_rehash ->
              (* A failed rehash is not the customer's problem: keep the old hash, it
                 still verifies, and try again next time. *)
              Password_hash.Hasher.hash hasher passcode
              |> Result.ok
              |> Option.value ~default:hash
            | Match | Mismatch -> hash
          in
          on_success (Set { s with hash; lockout = Lockout.record_success lockout })))
;;

let verify config ~hasher t ~passcode ~now =
  check config ~hasher t ~passcode ~now ~on_success:(fun record ->
    { record; result = Ok (); events = [] })
;;

let change config ~hasher t ~current ~new_passcode ~now =
  match t, Passcode_policy.check config.Config.policy new_passcode with
  | Not_set, _ -> fail t Not_set
  | Set _, Error v -> fail t (Weak v)
  | Set _, Ok () ->
    check config ~hasher t ~passcode:current ~now ~on_success:(fun record ->
      match new_hash config ~hasher new_passcode with
      | Error e -> { record; result = Error e; events = [] }
      | Ok hash ->
        { record = Set { hash; set_at = now; lockout = Lockout.initial }
        ; result = Ok ()
        ; events = [ Passcode_changed ]
        })
;;

let remove config ~hasher t ~passcode ~now =
  check config ~hasher t ~passcode ~now ~on_success:(fun _ ->
    { record = Not_set; result = Ok (); events = [ Passcode_removed ] })
;;

module Reset_proof = struct
  type t =
    { challenge_id : string
    ; verified_at : Time_ns.Stable.Alternate_sexp.V1.t
    }
  [@@deriving sexp_of, fields ~getters]

  let of_verified_code ~challenge_id ~verified_at = { challenge_id; verified_at }
end

let reset (config : Config.t) ~hasher t ~(proof : Reset_proof.t) ~new_passcode ~now =
  match t with
  | Not_set -> fail t Not_set
  | Set _ ->
    let age = Time_ns.diff now proof.verified_at in
    if Time_ns.Span.(age < zero || age > config.reset_proof_max_age)
    then fail t Stale_reset_proof
    else (
      match new_hash config ~hasher new_passcode with
      | Error e -> fail t e
      | Ok hash ->
        { record = Set { hash; set_at = now; lockout = Lockout.initial }
        ; result = Ok ()
        ; events = [ Passcode_reset ]
        })
;;
