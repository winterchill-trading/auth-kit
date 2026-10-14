open! Core
open Auth_kit

let show policy s =
  print_s
    [%message
      s
        ~check:
          (Passcode_policy.check policy s : (unit, Passcode_policy.Violation.t) Result.t)
        ~all:(Passcode_policy.violations policy s : Passcode_policy.Violation.t list)]
;;

let%expect_test "six digits" =
  List.iter
    [ "120587"; "000000"; "123456"; "654321"; "890123"; "12345"; "1234567"; "12a456"; "" ]
    ~f:(show Passcode_policy.six_digits);
  [%expect
    {|
    (120587 (check (Ok ())) (all ()))
    (000000 (check (Error All_same)) (all (All_same)))
    (123456 (check (Error Straight_run)) (all (Straight_run)))
    (654321 (check (Error Straight_run)) (all (Straight_run)))
    (890123 (check (Ok ())) (all ()))
    (12345 (check (Error Too_short)) (all (Too_short Straight_run)))
    (1234567 (check (Error Too_long)) (all (Too_long Straight_run)))
    (12a456 (check (Error Not_digits)) (all (Not_digits)))
    ("" (check (Error Too_short)) (all (Too_short)))
    |}]
;;

let%expect_test "deny list and wider lengths" =
  let policy =
    { (Passcode_policy.digits ~min_length:4 ~max_length:8) with
      deny = String.Set.of_list [ "1212"; "19840101" ]
    }
  in
  List.iter [ "1212"; "1213"; "19840101"; "13579"; "1" ] ~f:(show policy);
  [%expect
    {|
    (1212 (check (Error Denied)) (all (Denied)))
    (1213 (check (Ok ())) (all ()))
    (19840101 (check (Error Denied)) (all (Denied)))
    (13579 (check (Ok ())) (all ()))
    (1 (check (Error Too_short)) (all (Too_short)))
    |}]
;;

let%expect_test "violation names" =
  List.iter Passcode_policy.Violation.all ~f:(fun v ->
    printf
      "%s format=%b\n"
      (Passcode_policy.Violation.to_string v)
      (Passcode_policy.Violation.is_format v));
  [%expect
    {|
    too_short format=true
    too_long format=true
    not_digits format=true
    all_same format=false
    straight_run format=false
    denied format=false
    |}]
;;

let digit_string len =
  Quickcheck.Generator.(
    list_with_length len (Char.gen_uniform_inclusive '0' '9') >>| String.of_char_list)
;;

(* Brute force over all one million six-digit codes is cheap, but a property states the
   rule independently of the implementation: exactly 10 all-same codes and 10 runs (5 up
   from 0..4, 5 down from 5..9) are refused. *)
let%expect_test "exactly twenty six-digit codes are refused" =
  let refused = ref 0 in
  for i = 0 to 999_999 do
    match Passcode_policy.check Passcode_policy.six_digits (sprintf "%06d" i) with
    | Ok () -> ()
    | Error _ -> incr refused
  done;
  print_s [%sexp (!refused : int)];
  [%expect {| 20 |}]
;;

let%test_unit "accepted codes are never all-same or a run" =
  Quickcheck.test (digit_string 6) ~sexp_of:String.sexp_of_t ~f:(fun s ->
    match Passcode_policy.check Passcode_policy.six_digits s with
    | Error _ -> ()
    | Ok () ->
      let d = List.map (String.to_list s) ~f:Char.get_digit_exn in
      let diffs =
        List.map2_exn (List.drop_last_exn d) (List.tl_exn d) ~f:(fun a b -> b - a)
      in
      assert (not (List.for_all diffs ~f:(( = ) 0)));
      assert (not (List.for_all diffs ~f:(( = ) 1)));
      assert (not (List.for_all diffs ~f:(( = ) (-1)))))
;;
