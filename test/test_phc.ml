open! Core
open Auth_kit

let show s = print_s [%sexp (Phc.of_string s : Phc.t Or_error.t)]

let%expect_test "parse the reference Argon2id string" =
  let s =
    "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
  in
  show s;
  let t = Phc.of_string s |> Or_error.ok_exn in
  print_endline (Phc.to_string t);
  print_s [%sexp (Phc.param t "m" : string option), (Phc.param t "x" : string option)];
  [%expect
    {|
    (Ok
     ((id argon2id) (version (19)) (params ((m 65536) (t 2) (p 1)))
      (salt somesalt)
      (hash
       "\t1a\021\213\207$\237Z\021\163\026;\163&\229\2072\237\194G\002\152|\002\182Voa\145<\247")))
    $argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc
    ((65536) ())
    |}]
;;

let%expect_test "refusals" =
  List.iter
    [ "argon2id$v=19$m=1$c2FsdA$aGFzaA"
    ; "$Argon2id$m=1$c2FsdA$aGFzaA"
    ; "$argon2id$v=x$m=1$c2FsdA$aGFzaA"
    ; "$argon2id$m=1$c2FsdA"
    ; "$argon2id$m=1$c2FsdA==$aGFzaA"
    ; "$argon2id$m=1$c2FsdB$aGFzaA"
    ; "$argon2id$m=1$$aGFzaA"
    ; "$argon2id$m$c2FsdA$aGFzaA"
    ; "$argon2id$m=1,t=$c2FsdA$aGFzaA"
    ; "$pbkdf2-sha256$i=1000$c2FsdA$aGFzaA"
    ]
    ~f:show;
  [%expect
    {|
    (Error "PHC: bad algorithm id")
    (Error "PHC: bad algorithm id")
    (Error "PHC: bad version")
    (Error "PHC: expected $id[$v=n]$params$salt$hash")
    (Error (salt "base64: character outside the alphabet"))
    (Error (salt "base64: non-canonical trailing bits"))
    (Error ("PHC: empty field" salt))
    (Error ("PHC: bad parameter" m))
    (Error ("PHC: bad parameter" t=))
    (Ok
     ((id pbkdf2-sha256) (version ()) (params ((i 1000))) (salt salt)
      (hash hash)))
    |}]
;;

let%test_unit "base64 round trip" =
  Quickcheck.test String.quickcheck_generator ~sexp_of:String.sexp_of_t ~f:(fun s ->
    [%test_result: string Or_error.t] (Phc.B64.decode (Phc.B64.encode s)) ~expect:(Ok s))
;;

let%test_unit "decode accepts only canonical encodings" =
  (* Few distinct characters, including ones with low bits set, so non-canonical endings
     come up often. *)
  let gen =
    let open Quickcheck.Generator.Let_syntax in
    let%bind len = Int.gen_incl 0 8 in
    String.gen_with_length len (Quickcheck.Generator.of_list [ 'A'; 'B'; 'Q'; 'g'; '/' ])
  in
  Quickcheck.test gen ~sexp_of:String.sexp_of_t ~f:(fun s ->
    match Phc.B64.decode s with
    | Error _ -> ()
    | Ok raw -> [%test_result: string] (Phc.B64.encode raw) ~expect:s)
;;

let%test_unit "PHC round trip" =
  let name = String.gen_with_length 3 (Char.gen_uniform_inclusive 'a' 'z') in
  let value = String.gen_with_length 4 (Char.gen_uniform_inclusive '0' '9') in
  let gen =
    let open Quickcheck.Generator.Let_syntax in
    let%bind id = name
    and version = Option.quickcheck_generator (Int.gen_incl 0 100)
    and params = List.gen_non_empty (Quickcheck.Generator.both name value)
    and salt = String.gen_with_length 16 Char.quickcheck_generator
    and hash = String.gen_with_length 32 Char.quickcheck_generator in
    return { Phc.id; version; params; salt; hash }
  in
  Quickcheck.test gen ~sexp_of:Phc.sexp_of_t ~f:(fun t ->
    [%test_result: Phc.t Or_error.t] (Phc.of_string (Phc.to_string t)) ~expect:(Ok t))
;;
