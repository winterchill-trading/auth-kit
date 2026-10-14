open! Core
open! Async
open Auth_kit
module Hash = Auth_kit_hash

let t0 = Time_ns.of_string_with_utc_offset "2026-07-01 10:00:00Z"

let tiny : Password_hash.Scheme.t =
  Argon2id
    { memory_kib = 8
    ; iterations = 1
    ; parallelism = 1
    ; salt_length = 16
    ; hash_length = 32
    }
;;

let hasher = Hash.Kdf.hasher ~target:tiny ()
let config = Passcode.Config.default

let%expect_test "requirements" =
  let set = (Passcode.set config ~hasher Not_set ~passcode:"120587" ~now:t0).record in
  let req = Step_up_policy.Requirement.From_amount { threshold = 50_000 } in
  List.iter
    [ "always", set, Step_up_policy.Requirement.Always, None
    ; "never", set, Never, None
    ; "below", set, req, Some 49_999
    ; "at", set, req, Some 50_000
    ; "no rate", set, req, None
    ; "no passcode", Passcode.Not_set, Always, None
    ]
    ~f:(fun (label, passcode, r, amount) ->
      printf "%s: %b\n" label (Step_up_policy.required ~passcode r ~amount));
  [%expect
    {|
    always: true
    never: false
    below: false
    at: true
    no rate: true
    no passcode: false
    |}];
  return ()
;;

(* The issuer here is service-kit's grant store; any [unit -> 'grant] works. *)
module Purpose = struct
  type t =
    | Payment
    | Card_reveal
  [@@deriving sexp, compare, equal, enumerate]

  let to_string = function
    | Payment -> "payment"
    | Card_reveal -> "card_reveal"
  ;;

  let of_string s = List.find all ~f:(fun p -> String.equal (to_string p) s)
end

module Grants = Service_kit.Step_up.Make (Purpose) (Service_kit.Step_up.Memory_spent)

let%expect_test "earning a grant with the passcode, then using it" =
  let clock = Service_kit.Clock.Manual.create ~start:t0 in
  let grants =
    Grants.create
      ~key:(String.make 32 'k')
      ~spent:
        (Service_kit.Step_up.Memory_spent.create
           ~clock:(Service_kit.Clock.Manual.clock clock)
           ())
      ~clock:(Service_kit.Clock.Manual.clock clock)
      ()
  in
  let record =
    ref (Passcode.set config ~hasher Not_set ~passcode:"120587" ~now:t0).record
  in
  let step_up passcode =
    let o =
      Step_up_policy.with_passcode
        config
        ~hasher
        !record
        ~passcode
        ~purpose:(Purpose.to_string Payment)
        ~now:t0
        ~issue:(fun () -> Grants.issue grants ~session_id:"s-1" ~purpose:Payment)
    in
    record := o.record;
    print_s
      [%message
        ""
          ~result:
            (Result.map o.result ~f:(fun (_, (g : Grants.Grant.t)) ->
               Purpose.to_string g.purpose)
             : (string, Step_up_policy.Error.t) Result.t)
          ~events:(o.events : Security_log.Kind.t list)];
    o.result
  in
  let _ = step_up "000001" in
  let token =
    match step_up "120587" with
    | Ok (token, _) -> token
    | Error _ -> assert false
  in
  let%bind first = Grants.consume grants token ~session_id:"s-1" ~purpose:Payment in
  let%bind second = Grants.consume grants token ~session_id:"s-1" ~purpose:Payment in
  let other = Grants.check grants token ~session_id:"s-2" ~purpose:Payment in
  print_s
    [%message
      ""
        ~first:(Result.is_ok first : bool)
        ~second:(Result.error second : Service_kit.Step_up.Error.t option)
        ~other_session:(Result.error other : Service_kit.Step_up.Error.t option)];
  [%expect
    {|
    ((result (Error (Wrong (attempts_left 4))))
     (events ((Step_up_failed (purpose payment)))))
    ((result (Ok payment)) (events ()))
    ((first true) (second (Already_used)) (other_session (Wrong_session)))
    |}];
  return ()
;;

let%expect_test "a locked passcode blocks passkey step-ups too" =
  let record =
    ref (Passcode.set config ~hasher Not_set ~passcode:"120587" ~now:t0).record
  in
  for _ = 1 to 5 do
    record := (Passcode.verify config ~hasher !record ~passcode:"000001" ~now:t0).record
  done;
  let show label (r, events) =
    print_s
      [%message
        label
          ~result:
            (r : (string, [ `Not_verified | `Error of Step_up_policy.Error.t ]) Result.t)
          ~events:(events : Security_log.Kind.t list)]
  in
  let attempt ~verified ~now record =
    Step_up_policy.with_verified_factor
      config
      record
      ~verified
      ~purpose:"card_reveal"
      ~now
      ~issue:(fun () -> "grant")
  in
  show "locked" (attempt ~verified:true ~now:t0 !record);
  let later = Time_ns.add t0 Time_ns.Span.hour in
  show "after the lock" (attempt ~verified:true ~now:later !record);
  show "assertion failed" (attempt ~verified:false ~now:later !record);
  show "no passcode" (attempt ~verified:true ~now:later Not_set);
  [%expect
    {|
    (locked
     (result
      (Error (Error (Locked (until "2026-07-01 10:01:00Z") (retry_after 1m)))))
     (events ()))
    ("after the lock" (result (Ok grant)) (events ()))
    ("assertion failed" (result (Error Not_verified))
     (events ((Step_up_failed (purpose card_reveal)))))
    ("no passcode" (result (Error (Error Passcode_not_set))) (events ()))
    |}];
  return ()
;;
