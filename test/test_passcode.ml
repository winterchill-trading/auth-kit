open! Core
open Auth_kit
module Hash = Auth_kit_hash

let t0 = Time_ns.of_string_with_utc_offset "2026-07-01 10:00:00Z"
let at_sec s = Time_ns.add t0 (Time_ns.Span.of_int_sec s)

(* Minimal Argon2id costs keep the tests fast; production uses Argon2id.default. *)
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

(* Hashes are salted at random, so print the outcome without the record's hash. *)
let show ?(now = t0) label (o : unit Passcode.outcome) =
  print_s
    [%message
      label
        ~status:(Passcode.status config o.record ~now : Passcode.Status.t)
        ~result:(o.result : (unit, Passcode.Error.t) Result.t)
        ~events:(o.events : Security_log.Kind.t list)];
  o.record
;;

let%expect_test "set, verify, change, remove" =
  let r = Passcode.Not_set in
  let r = show "weak" (Passcode.set config ~hasher r ~passcode:"111111" ~now:t0) in
  let r = show "format" (Passcode.set config ~hasher r ~passcode:"12345" ~now:t0) in
  let r = show "set" (Passcode.set config ~hasher r ~passcode:"120587" ~now:t0) in
  let r = show "again" (Passcode.set config ~hasher r ~passcode:"530912" ~now:t0) in
  let r = show "verify" (Passcode.verify config ~hasher r ~passcode:"120587" ~now:t0) in
  let r =
    show
      "change, weak new one costs no attempt"
      (Passcode.change config ~hasher r ~current:"000001" ~new_passcode:"123456" ~now:t0)
  in
  let r =
    show
      "change, wrong current"
      (Passcode.change config ~hasher r ~current:"000001" ~new_passcode:"530912" ~now:t0)
  in
  let r =
    show
      "change"
      (Passcode.change config ~hasher r ~current:"120587" ~new_passcode:"530912" ~now:t0)
  in
  let r = show "old one" (Passcode.verify config ~hasher r ~passcode:"120587" ~now:t0) in
  let r = show "remove" (Passcode.remove config ~hasher r ~passcode:"530912" ~now:t0) in
  let _ =
    show "verify none" (Passcode.verify config ~hasher r ~passcode:"530912" ~now:t0)
  in
  [%expect
    {|
    (weak (status Not_set) (result (Error (Weak All_same))) (events ()))
    (format (status Not_set) (result (Error (Weak Too_short))) (events ()))
    (set (status (Set (set_at "2026-07-01 10:00:00Z"))) (result (Ok ()))
     (events (Passcode_set)))
    (again (status (Set (set_at "2026-07-01 10:00:00Z")))
     (result (Error Already_set)) (events ()))
    (verify (status (Set (set_at "2026-07-01 10:00:00Z"))) (result (Ok ()))
     (events ()))
    ("change, weak new one costs no attempt"
     (status (Set (set_at "2026-07-01 10:00:00Z")))
     (result (Error (Weak Straight_run))) (events ()))
    ("change, wrong current" (status (Set (set_at "2026-07-01 10:00:00Z")))
     (result (Error (Wrong (attempts_left 4)))) (events ()))
    (change (status (Set (set_at "2026-07-01 10:00:00Z"))) (result (Ok ()))
     (events (Passcode_changed)))
    ("old one" (status (Set (set_at "2026-07-01 10:00:00Z")))
     (result (Error (Wrong (attempts_left 4)))) (events ()))
    (remove (status Not_set) (result (Ok ())) (events (Passcode_removed)))
    ("verify none" (status Not_set) (result (Error Not_set)) (events ()))
    |}]
;;

let%expect_test "lockout through wrong passcodes, then reset" =
  let r =
    ref (Passcode.set config ~hasher Passcode.Not_set ~passcode:"120587" ~now:t0).record
  in
  let attempt ~sec passcode =
    let now = at_sec sec in
    r
    := show
         ~now
         (sprintf "t+%ds %s" sec passcode)
         (Passcode.verify config ~hasher !r ~passcode ~now)
  in
  List.iter [ 1; 2; 3; 4; 5 ] ~f:(fun s -> attempt ~sec:s "000001");
  (* Locked: even the right passcode is not checked. *)
  attempt ~sec:30 "120587";
  attempt ~sec:70 "000001";
  let proof =
    Passcode.Reset_proof.of_verified_code ~challenge_id:"ch-1" ~verified_at:(at_sec 80)
  in
  let reset ~sec new_passcode =
    let now = at_sec sec in
    r
    := show
         ~now
         (sprintf "reset t+%ds" sec)
         (Passcode.reset config ~hasher !r ~proof ~new_passcode ~now)
  in
  reset ~sec:(80 + 601) "530912";
  reset ~sec:90 "530912";
  attempt ~sec:91 "530912";
  [%expect
    {|
    ("t+1s 000001" (status (Set (set_at "2026-07-01 10:00:00Z")))
     (result (Error (Wrong (attempts_left 4)))) (events ()))
    ("t+2s 000001" (status (Set (set_at "2026-07-01 10:00:00Z")))
     (result (Error (Wrong (attempts_left 3)))) (events ()))
    ("t+3s 000001" (status (Set (set_at "2026-07-01 10:00:00Z")))
     (result (Error (Wrong (attempts_left 2)))) (events ()))
    ("t+4s 000001" (status (Set (set_at "2026-07-01 10:00:00Z")))
     (result (Error (Wrong (attempts_left 1)))) (events ()))
    ("t+5s 000001"
     (status
      (Locked (set_at "2026-07-01 10:00:00Z") (until "2026-07-01 10:01:05Z")
       (retry_after 1m)))
     (result (Error (Locked (until "2026-07-01 10:01:05Z") (retry_after 1m))))
     (events ((Passcode_locked (retry_after_seconds 60)))))
    ("t+30s 120587"
     (status
      (Locked (set_at "2026-07-01 10:00:00Z") (until "2026-07-01 10:01:05Z")
       (retry_after 35s)))
     (result (Error (Locked (until "2026-07-01 10:01:05Z") (retry_after 35s))))
     (events ()))
    ("t+70s 000001"
     (status
      (Locked (set_at "2026-07-01 10:00:00Z") (until "2026-07-01 10:03:10Z")
       (retry_after 2m)))
     (result (Error (Locked (until "2026-07-01 10:03:10Z") (retry_after 2m))))
     (events ((Passcode_locked (retry_after_seconds 120)))))
    ("reset t+681s" (status (Set (set_at "2026-07-01 10:00:00Z")))
     (result (Error Stale_reset_proof)) (events ()))
    ("reset t+90s" (status (Set (set_at "2026-07-01 10:01:30Z")))
     (result (Ok ())) (events (Passcode_reset)))
    ("t+91s 530912" (status (Set (set_at "2026-07-01 10:01:30Z")))
     (result (Ok ())) (events ()))
    |}]
;;

let%expect_test "an outdated scheme is upgraded on the next correct entry" =
  let pbkdf2 =
    Password_hash.Hasher.with_target
      hasher
      (Pbkdf2_sha256 { iterations = 1000; salt_length = 16; hash_length = 32 })
  in
  let r =
    (Passcode.set config ~hasher:pbkdf2 Passcode.Not_set ~passcode:"120587" ~now:t0)
      .record
  in
  let scheme (r : Passcode.t) =
    match r with
    | Not_set -> "none"
    | Set { hash; _ } -> Password_hash.Scheme.id hash.scheme
  in
  print_endline (scheme r);
  let wrong = (Passcode.verify config ~hasher r ~passcode:"000001" ~now:t0).record in
  print_endline (scheme wrong);
  let right = (Passcode.verify config ~hasher wrong ~passcode:"120587" ~now:t0).record in
  print_endline (scheme right);
  let again = Passcode.verify config ~hasher right ~passcode:"120587" ~now:t0 in
  print_s [%sexp (again.result : (unit, Passcode.Error.t) Result.t)];
  [%expect {|
    pbkdf2-sha256
    pbkdf2-sha256
    argon2id
    (Ok ())
    |}]
;;

let%expect_test "error codes and stable digest" =
  print_endline [%bin_digest: Passcode.Stable.V1.t];
  List.iter
    [ Passcode.Error.Weak All_same
    ; Already_set
    ; Not_set
    ; Wrong { attempts_left = 2 }
    ; Locked { until = t0; retry_after = Time_ns.Span.minute }
    ; Stale_reset_proof
    ; Hash_failed (Error.of_string "x")
    ]
    ~f:(fun e -> print_endline (Passcode.Error.code e));
  [%expect
    {|
    f65a7ddb7367abc57383ea4bdc24e7fa
    weak
    already_set
    not_set
    wrong
    locked
    stale_reset_proof
    hash_failed
    |}]
;;

module Op = struct
  type t =
    | Set of string
    | Verify of string
    | Change of string * string
    | Remove of string
    | Reset of string
    | Wait of int
  [@@deriving sexp_of]

  (* A handful of passcodes so guesses hit the right one often. *)
  let passcode = Quickcheck.Generator.of_list [ "120587"; "530912"; "111111"; "864201" ]

  let gen =
    let open Quickcheck.Generator in
    weighted_union
      [ 1., map passcode ~f:(fun p -> Set p)
      ; 4., map passcode ~f:(fun p -> Verify p)
      ; 1., map (both passcode passcode) ~f:(fun (a, b) -> Change (a, b))
      ; 1., map passcode ~f:(fun p -> Remove p)
      ; 1., map passcode ~f:(fun p -> Reset p)
      ; 2., map (Int.gen_incl 1 4000) ~f:(fun s -> Wait s)
      ]
  ;;
end

(* A model holding only the plain passcode: every accepted check must agree with it, and
   an unlocked check of the right passcode must be accepted. *)
let%test_unit "passcode operations agree with a plain model" =
  let ok r = Result.is_ok r in
  let strong p = Result.is_ok (Passcode_policy.check config.policy p) in
  Quickcheck.test
    ~trials:300
    (List.gen_with_length 25 Op.gen)
    ~sexp_of:[%sexp_of: Op.t list]
    ~f:(fun ops ->
      ignore
        (List.fold ops ~init:(Passcode.Not_set, None, t0) ~f:(fun (r, model, now) op ->
           let unlocked =
             match Passcode.status config r ~now with
             | Locked _ -> false
             | Not_set | Set _ -> true
           in
           let is_current p = [%equal: string option] model (Some p) in
           match op with
           | Wait s -> r, model, Time_ns.add now (Time_ns.Span.of_int_sec s)
           | Set p ->
             let o = Passcode.set config ~hasher r ~passcode:p ~now in
             [%test_result: bool] (ok o.result) ~expect:(Option.is_none model && strong p);
             o.record, (if ok o.result then Some p else model), now
           | Verify p ->
             let o = Passcode.verify config ~hasher r ~passcode:p ~now in
             [%test_result: bool] (ok o.result) ~expect:(unlocked && is_current p);
             o.record, model, now
           | Change (c, n) ->
             let o = Passcode.change config ~hasher r ~current:c ~new_passcode:n ~now in
             [%test_result: bool]
               (ok o.result)
               ~expect:(unlocked && is_current c && strong n);
             o.record, (if ok o.result then Some n else model), now
           | Remove p ->
             let o = Passcode.remove config ~hasher r ~passcode:p ~now in
             [%test_result: bool] (ok o.result) ~expect:(unlocked && is_current p);
             o.record, (if ok o.result then None else model), now
           | Reset p ->
             let proof =
               Passcode.Reset_proof.of_verified_code ~challenge_id:"c" ~verified_at:now
             in
             let o = Passcode.reset config ~hasher r ~proof ~new_passcode:p ~now in
             [%test_result: bool] (ok o.result) ~expect:(Option.is_some model && strong p);
             o.record, (if ok o.result then Some p else model), now)
         : Passcode.t * string option * Time_ns.t))
;;
