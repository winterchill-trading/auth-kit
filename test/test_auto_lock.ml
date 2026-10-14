open! Core
open Auth_kit

let%expect_test "choosing a period" =
  let try_ ~current ~passcode_set minutes =
    print_s
      [%sexp
        (Auto_lock.set ~current ~passcode_set ~minutes ()
         : (Auto_lock.t * Security_log.Kind.t option, Auto_lock.Error.t) Result.t)]
  in
  try_ ~current:Off ~passcode_set:true (Some 5);
  try_ ~current:(After { minutes = 5 }) ~passcode_set:true (Some 5);
  try_ ~current:(After { minutes = 5 }) ~passcode_set:true None;
  try_ ~current:Off ~passcode_set:false (Some 5);
  try_ ~current:Off ~passcode_set:false None;
  try_ ~current:Off ~passcode_set:true (Some 7);
  [%expect
    {|
    (Ok ((After (minutes 5)) ((Auto_lock_changed (minutes (5))))))
    (Ok ((After (minutes 5)) ()))
    (Ok (Off ((Auto_lock_changed (minutes ())))))
    (Error Passcode_required)
    (Ok (Off ()))
    (Error (Not_a_choice (minutes 7)))
    |}]
;;

let%expect_test "idle check" =
  let t0 = Time_ns.of_string_with_utc_offset "2026-07-01 10:00:00Z" in
  List.iter [ 0; 299; 300; 301 ] ~f:(fun s ->
    printf
      "%ds idle: %b\n"
      s
      (Auto_lock.is_locked
         (After { minutes = 5 })
         ~last_interaction:t0
         ~now:(Time_ns.add t0 (Time_ns.Span.of_int_sec s))));
  print_s [%sexp (Auto_lock.on_passcode_removed (After { minutes = 1 }) : Auto_lock.t)];
  print_endline [%bin_digest: Auto_lock.Stable.V1.t];
  [%expect
    {|
    0s idle: false
    299s idle: false
    300s idle: true
    301s idle: true
    Off
    ffb6a624f1671ee684ec96efea70a5be
    |}]
;;
