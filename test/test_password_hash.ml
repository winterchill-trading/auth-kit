open! Core
open Auth_kit
module Hash = Auth_kit_hash

let hex s = String.concat_map s ~f:(fun c -> sprintf "%02x" (Char.to_int c))

let%expect_test "RFC 9106 section 5.3 Argon2id test vector" =
  let p : Password_hash.Argon2id.t =
    { memory_kib = 32
    ; iterations = 3
    ; parallelism = 4
    ; salt_length = 16
    ; hash_length = 32
    }
  in
  Hash.Argon2id.derive
    p
    ~password:(String.make 32 '\x01')
    ~salt:(String.make 16 '\x02')
    ~secret_key:(String.make 8 '\x03')
    ~associated_data:(String.make 12 '\x04')
  |> Or_error.ok_exn
  |> hex
  |> print_endline;
  [%expect {| 0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659 |}]
;;

let%expect_test "reference implementation vector (password, somesalt)" =
  let stored =
    Password_hash.of_string
      "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
    |> Or_error.ok_exn
  in
  let hasher = Hash.Kdf.hasher () in
  let check secret =
    print_s
      [%sexp
        (secret : string)
        , (Password_hash.verify hasher stored secret
           : Password_hash.Verification.t Or_error.t)]
  in
  check "password";
  check "Password";
  [%expect {|
    (password (Ok Match_rehash))
    (Password (Ok Mismatch))
    |}]
;;

let%expect_test "RFC 7914 section 11 PBKDF2-HMAC-SHA256 vectors" =
  print_endline
    (hex
       (Hash.Pbkdf2_sha256.derive
          ~iterations:1
          ~length:64
          ~salt:"salt"
          ~password:"passwd"));
  print_endline
    (hex
       (Hash.Pbkdf2_sha256.derive
          ~iterations:80000
          ~length:64
          ~salt:"NaCl"
          ~password:"Password"));
  [%expect
    {|
    55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783
    4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d
    |}]
;;

(* Cheap costs so the tests stay fast; production uses Argon2id.default. *)
let cheap : Password_hash.Scheme.t =
  Argon2id
    { memory_kib = 64
    ; iterations = 1
    ; parallelism = 1
    ; salt_length = 16
    ; hash_length = 32
    }
;;

let hasher = Hash.Kdf.hasher ~target:cheap ()

let%expect_test "hash, verify, rehash after a cost change" =
  let stored = Password_hash.Hasher.hash hasher "120587" |> Or_error.ok_exn in
  let s = Password_hash.to_string stored in
  (* The salt is random; print the scheme part only. *)
  print_endline (String.prefix s 28);
  let back = Password_hash.of_string s |> Or_error.ok_exn in
  assert (Password_hash.equal stored back);
  let verify h secret =
    print_s
      [%sexp
        (Password_hash.verify h back secret : Password_hash.Verification.t Or_error.t)]
  in
  verify hasher "120587";
  verify hasher "120588";
  let stronger =
    Password_hash.Hasher.with_target
      hasher
      (Argon2id
         { memory_kib = 128
         ; iterations = 1
         ; parallelism = 1
         ; salt_length = 16
         ; hash_length = 32
         })
  in
  verify stronger "120587";
  verify stronger "000000";
  [%expect
    {|
    $argon2id$v=19$m=64,t=1,p=1$
    (Ok Match)
    (Ok Mismatch)
    (Ok Match_rehash)
    (Ok Mismatch)
    |}]
;;

let%expect_test "hex PBKDF2 hashes verify and ask to be rehashed" =
  let salt = "0123456789abcdef" in
  let dk =
    Hash.Pbkdf2_sha256.derive ~iterations:1000 ~length:32 ~salt ~password:"hunter22"
  in
  let legacy = sprintf "pbkdf2-sha256$1000$%s$%s" (hex salt) (hex dk) in
  let stored = Password_hash.of_string legacy |> Or_error.ok_exn in
  print_s [%sexp (stored.scheme : Password_hash.Scheme.t)];
  print_endline (Password_hash.to_string stored);
  print_s
    [%sexp
      (Password_hash.verify hasher stored "hunter22"
       : Password_hash.Verification.t Or_error.t)
      , (Password_hash.verify hasher stored "hunter23"
         : Password_hash.Verification.t Or_error.t)];
  (* The PHC form of the same hash reads back to the same value. *)
  assert (
    Password_hash.equal
      stored
      (Password_hash.of_string (Password_hash.to_string stored) |> Or_error.ok_exn));
  [%expect
    {|
    (Pbkdf2_sha256 ((iterations 1000) (salt_length 16) (hash_length 32)))
    $pbkdf2-sha256$i=1000$MDEyMzQ1Njc4OWFiY2RlZg$ueBbYQVkDHSR2wInfuEbu55EoAdDx3ozbiXKophExIU
    ((Ok Match_rehash) (Ok Mismatch))
    |}]
;;

let%expect_test "stored hashes outside the limits are refused" =
  List.iter
    [ "$argon2id$v=19$m=67108864,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
    ; "$argon2id$v=19$m=4,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
    ; "$argon2id$v=16$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
    ; "$argon2id$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
    ; "$argon2id$v=19$m=65536,t=2,p=1,k=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
    ; "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
    ; "$argon2id$v=19$m=65536,t=2,p=1$c2FsdA$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
    ; "$pbkdf2-sha256$i=99999999$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
    ; "pbkdf2-sha256$1000$zz$00"
    ]
    ~f:(fun s ->
      print_s
        [%sexp (Password_hash.of_string s |> Result.map ~f:ignore : unit Or_error.t)]);
  [%expect
    {|
    (Error ("hash cost out of range" memory (v 67108864) (lo 8) (hi 1048576)))
    (Error ("hash cost out of range" memory (v 4) (lo 8) (hi 1048576)))
    (Error ("unsupported Argon2 version" (v (16))))
    (Error ("unsupported Argon2 version" (v ())))
    (Error ("unknown parameter" k))
    (Error ("unsupported scheme" argon2i))
    (Error ("hash cost out of range" "salt length" (v 4) (lo 8) (hi 64)))
    (Error
     ("hash cost out of range" iterations (v 99999999) (lo 1) (hi 10000000)))
    (Error "bad hex")
    |}]
;;

let%expect_test "a derivation returning the wrong length is an error, not a mismatch" =
  let broken =
    Password_hash.Hasher.create
      ~target:cheap
      ~derive:(fun _ ~salt:_ ~secret:_ -> Ok "short")
      ~random:(fun n -> String.make n 'x')
      ()
  in
  print_s
    [%sexp
      (Password_hash.Hasher.hash broken "1" |> Result.map ~f:ignore : unit Or_error.t)];
  [%expect
    {| (Error ("derivation returned the wrong length" (hash_length 32) (got 5))) |}]
;;

let%expect_test "stable form" =
  print_endline [%bin_digest: Password_hash.Stable.V1.t];
  let stored = Password_hash.Hasher.hash hasher "1" |> Or_error.ok_exn in
  let bin = Binable.to_string (module Password_hash.Stable.V1) stored in
  assert (
    Password_hash.equal stored (Binable.of_string (module Password_hash.Stable.V1) bin));
  assert (
    Password_hash.equal
      stored
      (Password_hash.Stable.V1.t_of_sexp (Password_hash.Stable.V1.sexp_of_t stored)));
  [%expect {| bbdf8b39163c0570811f18fb79e8ed51 |}]
;;

let%test_unit "constant_time_equal agrees with String.equal" =
  Quickcheck.test
    (Quickcheck.Generator.both String.quickcheck_generator String.quickcheck_generator)
    ~sexp_of:[%sexp_of: string * string]
    ~f:(fun (a, b) ->
      [%test_result: bool]
        (Password_hash.constant_time_equal a b)
        ~expect:(String.equal a b);
      assert (Password_hash.constant_time_equal a a))
;;
