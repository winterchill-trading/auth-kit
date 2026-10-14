open! Core

module Requirement = struct
  type t =
    | Always
    | From_amount of { threshold : int }
    | Never
  [@@deriving sexp, compare, equal]

  let applies t ~amount =
    match t, amount with
    | Always, _ -> true
    | Never, _ -> false
    | From_amount _, None -> true
    | From_amount { threshold }, Some a -> a >= threshold
  ;;
end

let required ~passcode requirement ~amount =
  Passcode.is_set passcode && Requirement.applies requirement ~amount
;;

module Method = struct
  type t =
    | Passcode
    | Passkey
  [@@deriving sexp, compare, equal, enumerate]

  let to_string = function
    | Passcode -> "passcode"
    | Passkey -> "webauthn"
  ;;
end

module Error = struct
  type t =
    | Passcode_not_set
    | Wrong of { attempts_left : int }
    | Locked of
        { until : Time_ns.Stable.Alternate_sexp.V1.t
        ; retry_after : Time_ns.Span.t
        }
    | Hash_failed of Core.Error.t
  [@@deriving sexp_of]

  let code = function
    | Passcode_not_set -> "passcode_not_set"
    | Wrong _ -> "wrong"
    | Locked _ -> "locked"
    | Hash_failed _ -> "hash_failed"
  ;;
end

type 'grant outcome =
  { record : Passcode.t
  ; result : ('grant, Error.t) Result.t
  ; events : Security_log.Kind.t list
  }

let with_passcode config ~hasher record ~passcode ~purpose ~now ~issue =
  let o = Passcode.verify config ~hasher record ~passcode ~now in
  let failed = Security_log.Kind.Step_up_failed { purpose } in
  let error e = { record = o.record; result = Error e; events = failed :: o.events } in
  match o.result with
  | Ok () -> { record = o.record; result = Ok (issue ()); events = o.events }
  | Error (Wrong { attempts_left }) -> error (Wrong { attempts_left })
  | Error (Locked { until; retry_after }) -> error (Locked { until; retry_after })
  | Error (Hash_failed e) ->
    { record = o.record; result = Error (Hash_failed e); events = o.events }
  | Error Not_set -> { record = o.record; result = Error Passcode_not_set; events = [] }
  | Error ((Weak _ | Already_set | Stale_reset_proof) as e) ->
    (* [Passcode.verify] never answers these. *)
    raise_s [%message "Step_up_policy: unexpected passcode error" (e : Passcode.Error.t)]
;;

let with_verified_factor config record ~verified ~purpose ~now ~issue =
  match Passcode.status config record ~now with
  | Not_set -> Error (`Error Error.Passcode_not_set), []
  | Locked { until; retry_after; _ } ->
    Error (`Error (Error.Locked { until; retry_after })), []
  | Set _ ->
    if verified
    then Ok (issue ()), []
    else Error `Not_verified, [ Security_log.Kind.Step_up_failed { purpose } ]
;;
