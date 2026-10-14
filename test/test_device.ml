open! Core
open Auth_kit

let t0 = Time_ns.of_string_with_utc_offset "2026-05-11 12:00:00Z"
let at_min m = Time_ns.add t0 (Time_ns.Span.of_int_min m)

let%expect_test "address prefixes" =
  List.iter
    [ "203.0.113.7"
    ; "10.1.2.3"
    ; "256.1.1.1"
    ; "1.2.3"
    ; "2001:db8:85a3::8a2e:370:7334"
    ; "2001:0DB8:85A3:0000:0000:8A2E:0370:7334"
    ; "2001::1"
    ; "::1"
    ; "::"
    ; "::ffff:198.51.100.20"
    ; "64:ff9b::192.0.2.33"
    ; "fe80::1%en0"
    ; "1:2:3:4:5:6:7:8:9"
    ; "1::2::3"
    ; "12345::"
    ; "example.com"
    ; ""
    ]
    ~f:(fun a ->
      print_s
        [%sexp (a : string), (Device.Ip_prefix.of_address a : Device.Ip_prefix.t option)]);
  [%expect
    {|
    (203.0.113.7 (203.0))
    (10.1.2.3 (10.1))
    (256.1.1.1 ())
    (1.2.3 ())
    (2001:db8:85a3::8a2e:370:7334 (2001:db8:85a3))
    (2001:0DB8:85A3:0000:0000:8A2E:0370:7334 (2001:db8:85a3))
    (2001::1 (2001:0:0))
    (::1 (0:0:0))
    (:: (0:0:0))
    (::ffff:198.51.100.20 (198.51))
    (64:ff9b::192.0.2.33 (64:ff9b:0))
    (fe80::1%en0 (fe80:0:0))
    (1:2:3:4:5:6:7:8:9 ())
    (1::2::3 ())
    (12345:: ())
    (example.com ())
    ("" ())
    |}]
;;

let lifetime = Time_ns.Span.of_day 30.

let phone =
  Device.create
    ~id:"phone"
    ~user_agent:"App/3.1 (iOS 19)"
    ~ip_address:"203.0.113.7"
    ~now:t0
    ~lifetime
    ()
;;

let%expect_test "touch writes at most every five minutes" =
  let d = ref phone in
  List.iter [ 0; 1; 4; 5; 6; 9; 10; 60 ] ~f:(fun m ->
    match Device.touch !d ~now:(at_min m) with
    | None -> printf "%d: no write\n" m
    | Some d' ->
      d := d';
      printf "%d: write\n" m);
  print_s [%sexp (!d : Device.t)];
  [%expect
    {|
    0: write
    1: no write
    4: no write
    5: write
    6: no write
    9: no write
    10: write
    60: write
    ((id phone) (user_agent ("App/3.1 (iOS 19)")) (ip_prefix (203.0))
     (signed_in_at "2026-05-11 12:00:00Z")
     (last_active_at ("2026-05-11 13:00:00Z"))
     (expires_at "2026-06-10 12:00:00Z") (signed_out_at ()))
    |}]
;;

let%expect_test "list, sign out one, sign out others" =
  let laptop =
    Device.create ~id:"laptop" ~ip_address:"2001:db8:1::5" ~now:(at_min 10) ~lifetime ()
  in
  let tablet = Device.create ~id:"tablet" ~now:(at_min 20) ~lifetime () in
  let old = Device.create ~id:"old" ~now:(at_min (-60 * 24 * 31)) ~lifetime () in
  let devices = [ phone; laptop; tablet; old ] in
  let show devices =
    Device.list devices ~current:"phone" ~now:(at_min 30)
    |> List.map ~f:(fun (v : Device.View.t) -> v.device.id, v.current)
    |> [%sexp_of: (string * bool) list]
    |> print_s
  in
  show devices;
  let devices, kind =
    Device.sign_out_one devices ~id:"laptop" ~current:"phone" ~now:(at_min 30)
  in
  print_s [%sexp (kind : Security_log.Kind.t option)];
  show devices;
  let _, again =
    Device.sign_out_one devices ~id:"laptop" ~current:"phone" ~now:(at_min 31)
  in
  let _, expired =
    Device.sign_out_one devices ~id:"old" ~current:"phone" ~now:(at_min 31)
  in
  print_s
    [%sexp (again : Security_log.Kind.t option), (expired : Security_log.Kind.t option)];
  let devices, count, kind =
    Device.sign_out_others devices ~current:"phone" ~now:(at_min 32)
  in
  print_s [%sexp (count : int), (kind : Security_log.Kind.t)];
  show devices;
  [%expect
    {|
    ((phone true) (tablet false) (laptop false))
    ((Device_signed_out (device laptop) (this_device false)))
    ((phone true) (tablet false))
    (() ())
    (1 (Other_devices_signed_out (count 1)))
    ((phone true))
    |}]
;;

let%expect_test "stable digest" =
  print_endline [%bin_digest: Device.Stable.V1.t];
  [%expect {| ca6c81f07231c1b19021922d635bc82b |}]
;;

let%test_unit "IPv4 prefixes are the first two octets" =
  Quickcheck.test
    (Quickcheck.Generator.list_with_length 4 (Int.gen_incl 0 255))
    ~sexp_of:[%sexp_of: int list]
    ~f:(fun octets ->
      let addr = String.concat ~sep:"." (List.map octets ~f:Int.to_string) in
      let expect = sprintf "%d.%d" (List.nth_exn octets 0) (List.nth_exn octets 1) in
      [%test_result: string option]
        (Option.map (Device.Ip_prefix.of_address addr) ~f:Device.Ip_prefix.to_string)
        ~expect:(Some expect);
      [%test_result: string option]
        (Option.map
           (Device.Ip_prefix.of_address ("::ffff:" ^ addr))
           ~f:Device.Ip_prefix.to_string)
        ~expect:(Some expect))
;;

let%test_unit "IPv6 prefixes do not depend on how zeros are written" =
  Quickcheck.test
    (Quickcheck.Generator.list_with_length 8 (Int.gen_incl 0 3))
    ~sexp_of:[%sexp_of: int list]
    ~f:(fun groups ->
      (* Small values give many zero runs to compress. *)
      let full = String.concat ~sep:":" (List.map groups ~f:(sprintf "%04x")) in
      let short = String.concat ~sep:":" (List.map groups ~f:(sprintf "%x")) in
      let compressed =
        (* Replace the first run of zero groups (length >= 1) with "::". *)
        match List.findi groups ~f:(fun _ g -> g = 0) with
        | None -> short
        | Some (i, _) ->
          let run = List.length (List.take_while (List.drop groups i) ~f:(( = ) 0)) in
          let part l = String.concat ~sep:":" (List.map l ~f:(sprintf "%x")) in
          part (List.take groups i) ^ "::" ^ part (List.drop groups (i + run))
      in
      let p a =
        Option.map (Device.Ip_prefix.of_address a) ~f:Device.Ip_prefix.to_string
      in
      let expect =
        match groups with
        | [ 0; 0; 0; 0; 0; 0xffff; _; _ ] -> p full
        | g0 :: g1 :: g2 :: _ -> Some (sprintf "%x:%x:%x" g0 g1 g2)
        | _ -> assert false
      in
      [%test_result: string option] (p full) ~expect;
      [%test_result: string option] (p short) ~expect;
      [%test_result: string option] (p compressed) ~expect)
;;
