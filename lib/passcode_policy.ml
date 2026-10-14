open! Core

module Violation = struct
  type t =
    | Too_short
    | Too_long
    | Not_digits
    | All_same
    | Straight_run
    | Denied
  [@@deriving sexp, compare, equal, enumerate]

  let to_string = function
    | Too_short -> "too_short"
    | Too_long -> "too_long"
    | Not_digits -> "not_digits"
    | All_same -> "all_same"
    | Straight_run -> "straight_run"
    | Denied -> "denied"
  ;;

  let is_format = function
    | Too_short | Too_long | Not_digits -> true
    | All_same | Straight_run | Denied -> false
  ;;
end

type t =
  { min_length : int
  ; max_length : int
  ; digits_only : bool
  ; reject_all_same : bool
  ; reject_straight_runs : bool
  ; deny : String.Set.t
  }
[@@deriving sexp, compare, equal]

let digits ~min_length ~max_length =
  if min_length < 1 then raise_s [%message "Passcode_policy.digits: min_length < 1"];
  if max_length < min_length
  then raise_s [%message "Passcode_policy.digits: max_length < min_length"];
  { min_length
  ; max_length
  ; digits_only = true
  ; reject_all_same = true
  ; reject_straight_runs = true
  ; deny = String.Set.empty
  }
;;

let six_digits = digits ~min_length:6 ~max_length:6

(* A single character is trivially "all the same" and "a run"; only flag those from two
   characters on, so a policy allowing length 1 still works. *)
let all_same s = String.length s >= 2 && String.for_all s ~f:(fun c -> Char.equal c s.[0])

let straight_run s =
  let n = String.length s in
  n >= 2
  && String.for_all s ~f:Char.is_digit
  &&
  let step i = Char.to_int s.[i + 1] - Char.to_int s.[i] in
  let first = step 0 in
  (first = 1 || first = -1)
  && List.for_all (List.range 1 (n - 1)) ~f:(fun i -> step i = first)
;;

let violations t s =
  let n = String.length s in
  List.filter Violation.all ~f:(function
    | Too_short -> n < t.min_length
    | Too_long -> n > t.max_length
    | Not_digits -> t.digits_only && not (String.for_all s ~f:Char.is_digit)
    | All_same -> t.reject_all_same && all_same s
    | Straight_run -> t.reject_straight_runs && straight_run s
    | Denied -> Set.mem t.deny s)
;;

let check t s =
  match violations t s with
  | [] -> Ok ()
  | v :: _ -> Error v
;;
