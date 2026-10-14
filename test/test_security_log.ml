open! Core
open Auth_kit
module Kind = Security_log.Kind

let t0 = Time_ns.of_string_with_utc_offset "2026-03-02 08:00:00Z"
let at_min m = Time_ns.add t0 (Time_ns.Span.of_int_min m)

let%expect_test "wire names are stable" =
  List.iter Kind.all_names ~f:print_endline;
  [%expect
    {|
    sign_in
    sign_out
    passcode_set
    passcode_changed
    passcode_reset
    passcode_removed
    step_up_failed
    passcode_locked
    biometric_enrolled
    biometric_removed
    device_signed_out
    other_devices_signed_out
    cards_frozen
    auto_lock_changed
    |}]
;;

let%expect_test "details" =
  List.iter
    [ Kind.Sign_in { new_device = true; new_user = false }
    ; Step_up_failed { purpose = "payment" }
    ; Passcode_locked { retry_after_seconds = 60 }
    ; Device_signed_out { device = "d-2"; this_device = false }
    ; Other_devices_signed_out { count = 3 }
    ; Auto_lock_changed { minutes = Some 5 }
    ; Auto_lock_changed { minutes = None }
    ; Passcode_set
    ]
    ~f:(fun k ->
      print_s
        [%sexp (Kind.name k : string), (Kind.detail k : (string * Kind.Detail.t) list)]);
  [%expect
    {|
    (sign_in ((newDevice (Bool true)) (newUser (Bool false))))
    (step_up_failed ((purpose (String payment))))
    (passcode_locked ((retryAfterSeconds (Int 60))))
    (device_signed_out ((device (String d-2)) (thisDevice (Bool false))))
    (other_devices_signed_out ((count (Int 3))))
    (auto_lock_changed ((minutes (Int 5))))
    (auto_lock_changed ((minutes Null)))
    (passcode_set ())
    |}]
;;

let sample_log () =
  let log = Security_log.empty in
  let add log ~m ?device kind =
    fst (Security_log.append log ~at:(at_min m) ?device kind)
  in
  let log =
    add log ~m:0 ~device:"phone" (Sign_in { new_device = true; new_user = true })
  in
  let log = add log ~m:1 ~device:"phone" Passcode_set in
  let log =
    add log ~m:600 ~device:"laptop" (Sign_in { new_device = true; new_user = false })
  in
  let log = add log ~m:601 ~device:"laptop" (Step_up_failed { purpose = "payment" }) in
  let log =
    add log ~m:3000 ~device:"tablet" (Sign_in { new_device = true; new_user = false })
  in
  let log =
    add log ~m:3001 ~device:"phone" (Sign_in { new_device = false; new_user = false })
  in
  add
    log
    ~m:3002
    ~device:"phone"
    (Device_signed_out { device = "tablet"; this_device = false })
;;

let%expect_test "recent and notices" =
  let log = sample_log () in
  let entries = Security_log.entries log in
  let brief es =
    List.map es ~f:(fun (e : Security_log.Entry.t) -> e.seq, Kind.name e.kind, e.device)
  in
  print_s
    [%sexp
      (brief (Security_log.recent entries ~limit:3) : (int * string * string option) list)];
  (* Seen from the phone: the first sign-ins of the laptop and the tablet in the last two
     days. The phone's own first sign-in is older than the window. *)
  print_s
    [%sexp
      (brief
         (Security_log.notices entries ~current_device:(Some "phone") ~now:(at_min 3005))
       : (int * string * string option) list)];
  print_s
    [%sexp
      (brief
         (Security_log.notices entries ~current_device:(Some "tablet") ~now:(at_min 3005))
       : (int * string * string option) list)];
  [%expect
    {|
    ((7 device_signed_out (phone)) (6 sign_in (phone)) (5 sign_in (tablet)))
    ((5 sign_in (tablet)) (3 sign_in (laptop)))
    ((3 sign_in (laptop)))
    |}]
;;

let%expect_test "time order and limits are enforced" =
  let log = sample_log () in
  print_s
    [%sexp
      (Or_error.try_with (fun () -> Security_log.append log ~at:t0 Sign_out)
       |> Result.is_error
       : bool)];
  print_s
    [%sexp
      (Or_error.try_with (fun () ->
         Security_log.recent (Security_log.entries log) ~limit:201)
       |> Result.is_error
       : bool)];
  [%expect {|
    true
    true
    |}]
;;

let%expect_test "stable digests" =
  print_endline [%bin_digest: Security_log.Stable.Kind.V1.t];
  print_endline [%bin_digest: Security_log.Stable.Entry.V1.t];
  let log = sample_log () in
  List.iter (Security_log.entries log) ~f:(fun e ->
    let back =
      Binable.of_string
        (module Security_log.Stable.Entry.V1)
        (Binable.to_string (module Security_log.Stable.Entry.V1) e)
    in
    assert (Security_log.Entry.equal e back));
  print_s
    [%sexp (List.last_exn (Security_log.entries log) : Security_log.Stable.Entry.V1.t)];
  [%expect
    {|
    ffba4409c04dfa267ff7eb52be58b4bb
    402256dcbb3149ebc29a1e86cb2e1fb1
    ((seq 7) (at "2026-03-04 10:02:00Z")
     (kind (Device_signed_out (device tablet) (this_device false)))
     (device (phone)) (user_agent ()) (ip_prefix ()))
    |}]
;;

let%test_unit "sequence numbers are dense and increasing" =
  Quickcheck.test
    (List.quickcheck_generator (Int.gen_incl 0 1000))
    ~sexp_of:[%sexp_of: int list]
    ~f:(fun gaps ->
      let log, _ =
        List.fold gaps ~init:(Security_log.empty, t0) ~f:(fun (log, at) gap ->
          let at = Time_ns.add at (Time_ns.Span.of_int_sec gap) in
          fst (Security_log.append log ~at Sign_out), at)
      in
      [%test_result: int list]
        (List.map (Security_log.entries log) ~f:(fun e -> e.seq))
        ~expect:(List.init (List.length gaps) ~f:succ))
;;
