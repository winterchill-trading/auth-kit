(* auth-kit: hash, verify and inspect stored hashes, time Argon2id costs, and check
   passcodes against the default rules. Secrets are read from stdin, never from the
   command line, so they stay out of shell history and process listings. *)

open! Core
open Auth_kit

let read_secret () =
  match In_channel.input_line In_channel.stdin with
  | Some line -> line
  | None -> ""
;;

let argon2_flags =
  let open Command.Let_syntax in
  let d = Password_hash.Argon2id.default in
  [%map_open
    let memory_kib =
      flag "-m" (optional_with_default d.memory_kib int) ~doc:"KIB memory (default 19456)"
    and iterations =
      flag "-t" (optional_with_default d.iterations int) ~doc:"N passes (default 2)"
    and parallelism =
      flag "-p" (optional_with_default d.parallelism int) ~doc:"N lanes (default 1)"
    in
    Password_hash.Scheme.Argon2id { d with memory_kib; iterations; parallelism }]
;;

let hash_cmd =
  Command.basic
    ~summary:"hash the secret on stdin with Argon2id and print the PHC string"
    (let%map_open.Command target = argon2_flags in
     fun () ->
       let hasher = Auth_kit_hash.Kdf.hasher ~target () in
       print_endline
         (Password_hash.to_string
            (Password_hash.Hasher.hash hasher (read_secret ()) |> Or_error.ok_exn)))
;;

let verify_cmd =
  Command.basic
    ~summary:"check the secret on stdin against a stored hash (exit 1 on mismatch)"
    ~readme:(fun () ->
      "Prints match, mismatch or match_rehash (correct, but stored under other costs than\n\
       the -m/-t/-p given, which default to the recommended ones).")
    (let%map_open.Command target = argon2_flags
     and stored = anon ("HASH" %: string) in
     fun () ->
       let hasher = Auth_kit_hash.Kdf.hasher ~target () in
       let stored = Password_hash.of_string stored |> Or_error.ok_exn in
       match Password_hash.verify hasher stored (read_secret ()) |> Or_error.ok_exn with
       | Match -> print_endline "match"
       | Match_rehash -> print_endline "match_rehash"
       | Mismatch ->
         print_endline "mismatch";
         exit 1)
;;

let inspect_cmd =
  Command.basic
    ~summary:"print the scheme and costs of a stored hash"
    (let%map_open.Command stored = anon ("HASH" %: string) in
     fun () ->
       let stored = Password_hash.of_string stored |> Or_error.ok_exn in
       print_s [%sexp (stored.scheme : Password_hash.Scheme.t)])
;;

let bench_cmd =
  Command.basic
    ~summary:"time Argon2id at the given costs"
    (let%map_open.Command target = argon2_flags
     and n = flag "-n" (optional_with_default 10 int) ~doc:"N hashes (default 10)" in
     fun () ->
       let hasher = Auth_kit_hash.Kdf.hasher ~target () in
       let start = Time_ns.now () in
       for _ = 1 to n do
         ignore
           (Password_hash.Hasher.hash hasher "120587" |> Or_error.ok_exn
            : Password_hash.t)
       done;
       let per =
         Time_ns.Span.to_ms (Time_ns.diff (Time_ns.now ()) start) /. Float.of_int n
       in
       printf
         "%s: %.1f ms per hash over %d\n"
         (Sexp.to_string [%sexp (target : Password_hash.Scheme.t)])
         per
         n)
;;

let check_cmd =
  Command.basic
    ~summary:"check the passcode on stdin against the six-digit rules"
    (Command.Param.return (fun () ->
       match Passcode_policy.violations Passcode_policy.six_digits (read_secret ()) with
       | [] -> print_endline "ok"
       | vs ->
         List.iter vs ~f:(fun v -> print_endline (Passcode_policy.Violation.to_string v));
         exit 1))
;;

let () =
  Command_unix.run
    (Command.group
       ~summary:"passcode hashing and checking tools"
       [ "hash", hash_cmd
       ; "verify", verify_cmd
       ; "inspect", inspect_cmd
       ; "bench", bench_cmd
       ; "check-passcode", check_cmd
       ])
;;
