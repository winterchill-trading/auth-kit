open! Core

module Stable = struct
  module Kind = struct
    module V1 = struct
      type t =
        | Sign_in of
            { new_device : bool
            ; new_user : bool
            }
        | Sign_out
        | Passcode_set
        | Passcode_changed
        | Passcode_reset
        | Passcode_removed
        | Step_up_failed of { purpose : string }
        | Passcode_locked of { retry_after_seconds : int }
        | Biometric_enrolled
        | Biometric_removed
        | Device_signed_out of
            { device : string
            ; this_device : bool
            }
        | Other_devices_signed_out of { count : int }
        | Cards_frozen of { count : int }
        | Auto_lock_changed of { minutes : int option }
      [@@deriving bin_io, sexp, compare, equal]
    end
  end

  module Entry = struct
    module V1 = struct
      type t =
        { seq : int
        ; at : Time_ns.Stable.Alternate_sexp.V1.t
        ; kind : Kind.V1.t
        ; device : string option
        ; user_agent : string option
        ; ip_prefix : string option
        }
      [@@deriving bin_io, sexp, compare, equal]
    end
  end
end

module Kind = struct
  include Stable.Kind.V1

  let name = function
    | Sign_in _ -> "sign_in"
    | Sign_out -> "sign_out"
    | Passcode_set -> "passcode_set"
    | Passcode_changed -> "passcode_changed"
    | Passcode_reset -> "passcode_reset"
    | Passcode_removed -> "passcode_removed"
    | Step_up_failed _ -> "step_up_failed"
    | Passcode_locked _ -> "passcode_locked"
    | Biometric_enrolled -> "biometric_enrolled"
    | Biometric_removed -> "biometric_removed"
    | Device_signed_out _ -> "device_signed_out"
    | Other_devices_signed_out _ -> "other_devices_signed_out"
    | Cards_frozen _ -> "cards_frozen"
    | Auto_lock_changed _ -> "auto_lock_changed"
  ;;

  (* One sample per constructor; the match in [name] makes the compiler point here when a
     constructor is added. *)
  let all_names =
    List.map
      ~f:name
      [ Sign_in { new_device = false; new_user = false }
      ; Sign_out
      ; Passcode_set
      ; Passcode_changed
      ; Passcode_reset
      ; Passcode_removed
      ; Step_up_failed { purpose = "" }
      ; Passcode_locked { retry_after_seconds = 0 }
      ; Biometric_enrolled
      ; Biometric_removed
      ; Device_signed_out { device = ""; this_device = false }
      ; Other_devices_signed_out { count = 0 }
      ; Cards_frozen { count = 0 }
      ; Auto_lock_changed { minutes = None }
      ]
  ;;

  module Detail = struct
    type t =
      | Bool of bool
      | Int of int
      | String of string
      | Null
    [@@deriving sexp, compare, equal]
  end

  let detail : t -> (string * Detail.t) list = function
    | Sign_in { new_device; new_user } ->
      [ "newDevice", Bool new_device; "newUser", Bool new_user ]
    | Step_up_failed { purpose } -> [ "purpose", String purpose ]
    | Passcode_locked { retry_after_seconds } ->
      [ "retryAfterSeconds", Int retry_after_seconds ]
    | Device_signed_out { device; this_device } ->
      [ "device", String device; "thisDevice", Bool this_device ]
    | Other_devices_signed_out { count } | Cards_frozen { count } ->
      [ "count", Int count ]
    | Auto_lock_changed { minutes } ->
      [ ( "minutes"
        , Option.value_map minutes ~default:Detail.Null ~f:(fun m -> Detail.Int m) )
      ]
    | Sign_out
    | Passcode_set
    | Passcode_changed
    | Passcode_reset
    | Passcode_removed
    | Biometric_enrolled
    | Biometric_removed -> []
  ;;
end

module Entry = struct
  include Stable.Entry.V1
end

type t =
  { rev_entries : Entry.t list
  ; length : int
  }
[@@deriving sexp_of]

let empty = { rev_entries = []; length = 0 }

let append t ~at ?device ?user_agent ?ip_prefix kind =
  (match t.rev_entries with
   | last :: _ when Time_ns.( < ) at last.at ->
     raise_s
       [%message
         "Security_log.append: time goes backwards"
           ~last:(last.at : Time_ns.Stable.Alternate_sexp.V1.t)
           ~at:(at : Time_ns.Stable.Alternate_sexp.V1.t)]
   | _ -> ());
  let entry = { Entry.seq = t.length + 1; at; kind; device; user_agent; ip_prefix } in
  { rev_entries = entry :: t.rev_entries; length = t.length + 1 }, entry
;;

let entries t = List.rev t.rev_entries
let length t = t.length

let newest_first entries =
  List.sort entries ~compare:(fun (a : Entry.t) (b : Entry.t) ->
    Comparable.lift [%compare: Time_ns.t * int] ~f:(fun (e : Entry.t) -> e.at, e.seq) b a)
;;

let recent entries ~limit =
  if limit < 1 || limit > 200
  then raise_s [%message "Security_log.recent: limit must be 1-200" (limit : int)];
  List.take (newest_first entries) limit
;;

let notices ?(window = Time_ns.Span.of_day 2.) ?(max = 10) entries ~current_device ~now =
  let since = Time_ns.sub now window in
  newest_first entries
  |> List.filter ~f:(fun (e : Entry.t) ->
    Time_ns.( >= ) e.at since
    && Time_ns.( <= ) e.at now
    && (match e.kind with
        | Sign_in { new_device = true; _ } -> true
        | _ -> false)
    && not ([%equal: string option] e.device current_device && Option.is_some e.device))
  |> Fn.flip List.take max
;;
