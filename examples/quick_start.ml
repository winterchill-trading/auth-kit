(* A customer sets a passcode, mistypes it, gets locked out, resets it with a code sent to
   their address, signs out another device, and reads their security log. *)

open! Core
open Auth_kit

let () =
  (* Cheap Argon2id costs so the example runs instantly; leave [?target] out in a real
     service to get Argon2id.default (19 MiB, 2 passes). *)
  let hasher =
    Auth_kit_hash.Kdf.hasher
      ~target:
        (Argon2id
           { memory_kib = 64
           ; iterations = 1
           ; parallelism = 1
           ; salt_length = 16
           ; hash_length = 32
           })
      ()
  in
  let config = Passcode.Config.default in
  let t0 = Time_ns.of_string_with_utc_offset "2026-07-01 10:00:00Z" in
  let at s = Time_ns.add t0 (Time_ns.Span.of_int_sec s) in
  let log = ref Security_log.empty in
  let record = ref Passcode.Not_set in
  let run ~now label (o : unit Passcode.outcome) =
    record := o.record;
    List.iter o.events ~f:(fun kind ->
      log := fst (Security_log.append !log ~at:now ~device:"phone" kind));
    printf
      "%-22s %s\n"
      label
      (match o.result with
       | Ok () -> "ok"
       | Error e -> Sexp.to_string_hum (Passcode.Error.sexp_of_t e))
  in
  run
    ~now:t0
    "set 123456"
    (Passcode.set config ~hasher !record ~passcode:"123456" ~now:t0);
  run
    ~now:t0
    "set 120587"
    (Passcode.set config ~hasher !record ~passcode:"120587" ~now:t0);
  for i = 1 to 5 do
    run
      ~now:(at i)
      (sprintf "verify 000001 (#%d)" i)
      (Passcode.verify config ~hasher !record ~passcode:"000001" ~now:(at i))
  done;
  (* The service checked a one-time code issued for passcode reset. *)
  let proof =
    Passcode.Reset_proof.of_verified_code ~challenge_id:"ch-42" ~verified_at:(at 20)
  in
  run
    ~now:(at 30)
    "reset to 530912"
    (Passcode.reset config ~hasher !record ~proof ~new_passcode:"530912" ~now:(at 30));
  let phone =
    Device.create
      ~id:"phone"
      ~ip_address:"203.0.113.7"
      ~now:t0
      ~lifetime:(Time_ns.Span.of_day 30.)
      ()
  in
  let laptop =
    Device.create
      ~id:"laptop"
      ~ip_address:"2001:db8:85a3::1"
      ~now:(at 5)
      ~lifetime:(Time_ns.Span.of_day 30.)
      ()
  in
  let _devices, count, kind =
    Device.sign_out_others [ phone; laptop ] ~current:"phone" ~now:(at 40)
  in
  log := fst (Security_log.append !log ~at:(at 40) ~device:"phone" kind);
  printf "signed out %d other device(s)\n\nsecurity log, newest first:\n" count;
  List.iter
    (Security_log.recent (Security_log.entries !log) ~limit:50)
    ~f:(fun e ->
      printf
        "  #%d %s %s %s\n"
        e.seq
        (Time_ns.to_string_iso8601_basic e.at ~zone:Time_float.Zone.utc)
        (Security_log.Kind.name e.kind)
        (Sexp.to_string_hum
           [%sexp
             (Security_log.Kind.detail e.kind
              : (string * Security_log.Kind.Detail.t) list)]))
;;
