open! Core
open Auth_kit

let config = Lockout.Config.default
let t0 = Time_ns.of_string_with_utc_offset "2026-01-05 09:00:00Z"

let%expect_test "lock lengths per wrong attempt" =
  List.iter (List.range 1 14) ~f:(fun failures ->
    print_s
      [%message
        (failures : int) ~lock:(Lockout.lock_for config ~failures : Time_ns.Span.t option)]);
  [%expect
    {|
    ((failures 1) (lock ()))
    ((failures 2) (lock ()))
    ((failures 3) (lock ()))
    ((failures 4) (lock ()))
    ((failures 5) (lock (1m)))
    ((failures 6) (lock (2m)))
    ((failures 7) (lock (4m)))
    ((failures 8) (lock (8m)))
    ((failures 9) (lock (16m)))
    ((failures 10) (lock (32m)))
    ((failures 11) (lock (1h)))
    ((failures 12) (lock (1h)))
    ((failures 13) (lock (1h)))
    |}]
;;

let%expect_test "a customer guessing" =
  let t = ref Lockout.initial in
  let now = ref t0 in
  let wrong () =
    let t', status = Lockout.record_failure config !t ~now:!now in
    t := t';
    print_s [%message "wrong" (status : Lockout.Status.t)]
  in
  let wait span = now := Time_ns.add !now span in
  for _ = 1 to 5 do
    wrong ()
  done;
  (* Attempts while locked are not counted. *)
  wait (Time_ns.Span.of_sec 30.);
  wrong ();
  wait (Time_ns.Span.of_sec 30.);
  print_s [%sexp (Lockout.status config !t ~now:!now : Lockout.Status.t)];
  wrong ();
  wait (Time_ns.Span.of_min 2.);
  t := Lockout.record_success !t;
  print_s [%sexp (!t : Lockout.t)];
  [%expect
    {|
    (wrong (status (Open (attempts_left 4))))
    (wrong (status (Open (attempts_left 3))))
    (wrong (status (Open (attempts_left 2))))
    (wrong (status (Open (attempts_left 1))))
    (wrong (status (Locked (until "2026-01-05 09:01:00Z") (retry_after 1m))))
    (wrong (status (Locked (until "2026-01-05 09:01:00Z") (retry_after 30s))))
    (Open (attempts_left 1))
    (wrong (status (Locked (until "2026-01-05 09:03:00Z") (retry_after 2m))))
    ((failures 0) (locked_until ()))
    |}]
;;

let%expect_test "stable digest and sexp" =
  print_endline [%bin_digest: Lockout.Stable.V1.t];
  let t, _ =
    Lockout.record_failure
      (Lockout.Config.create
         ~free_attempts:1
         ~first_lock:Time_ns.Span.second
         ~max_lock:Time_ns.Span.second)
      Lockout.initial
      ~now:t0
  in
  let sexp = Lockout.Stable.V1.sexp_of_t t in
  print_s sexp;
  assert (Lockout.equal t (Lockout.Stable.V1.t_of_sexp sexp));
  print_s
    [%sexp
      (Or_error.try_with (fun () ->
         Lockout.Stable.V1.t_of_sexp (Sexp.of_string "((failures -1) (locked_until ()))"))
       |> Result.is_error
       : bool)];
  [%expect
    {|
    5c8c976075b263b2f60e7307e02a698b
    ((failures 1) (locked_until ("2026-01-05 09:00:01Z")))
    true
    |}]
;;

module Event = struct
  type t =
    | Wrong
    | Right
    | Wait of int (** seconds *)
  [@@deriving sexp_of]

  let quickcheck_generator =
    Quickcheck.Generator.weighted_union
      [ 8., Quickcheck.Generator.return Wrong
      ; 1., Quickcheck.Generator.return Right
      ; 3., Quickcheck.Generator.map (Int.gen_incl 1 7200) ~f:(fun s -> Wait s)
      ]
  ;;
end

let%test_unit "locks only after free attempts, never beyond the cap, never shorter" =
  Quickcheck.test
    (List.quickcheck_generator Event.quickcheck_generator)
    ~sexp_of:[%sexp_of: Event.t list]
    ~f:(fun events ->
      let _ =
        List.fold
          events
          ~init:(Lockout.initial, t0, Time_ns.Span.zero)
          ~f:(fun (t, now, last_lock) event ->
            match event with
            | Wait s -> t, Time_ns.add now (Time_ns.Span.of_int_sec s), last_lock
            | Right -> Lockout.record_success t, now, Time_ns.Span.zero
            | Wrong ->
              let before = Lockout.status config t ~now in
              let t', after = Lockout.record_failure config t ~now in
              (match before, after with
               | Locked _, _ ->
                 assert (Lockout.equal t t');
                 t', now, last_lock
               | Open _, Open { attempts_left } ->
                 assert (t'.failures < config.free_attempts);
                 assert (attempts_left = config.free_attempts - t'.failures);
                 t', now, last_lock
               | Open _, Locked { retry_after; _ } ->
                 assert (t'.failures >= config.free_attempts);
                 assert (Time_ns.Span.(retry_after <= config.max_lock));
                 assert (Time_ns.Span.(retry_after >= last_lock));
                 t', now, retry_after))
      in
      ())
;;
