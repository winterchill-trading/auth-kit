open! Core

module Stable = struct
  module V1 = struct
    type t =
      | Off
      | After of { minutes : int }
    [@@deriving bin_io, sexp, compare, equal]
  end
end

include Stable.V1

let default_choices = [ 1; 5; 15; 30 ]

module Error = struct
  type t =
    | Passcode_required
    | Not_a_choice of { minutes : int }
  [@@deriving sexp, compare, equal]

  let code = function
    | Passcode_required -> "passcode_required"
    | Not_a_choice _ -> "not_a_choice"
  ;;
end

let minutes = function
  | Off -> None
  | After { minutes } -> Some minutes
;;

let set ?(choices = default_choices) ~current ~passcode_set ~minutes:wanted () =
  let next =
    match wanted with
    | None -> Ok Off
    | Some m when not (List.mem choices m ~equal:Int.equal) ->
      Error (Error.Not_a_choice { minutes = m })
    | Some _ when not passcode_set -> Error Error.Passcode_required
    | Some m -> Ok (After { minutes = m })
  in
  Result.map next ~f:(fun next ->
    ( next
    , if equal next current
      then None
      else Some (Security_log.Kind.Auto_lock_changed { minutes = minutes next }) ))
;;

let on_passcode_removed _ = Off

let is_locked t ~last_interaction ~now =
  match t with
  | Off -> false
  | After { minutes } ->
    Time_ns.Span.( >= )
      (Time_ns.diff now last_interaction)
      (Time_ns.Span.of_int_min minutes)
;;
