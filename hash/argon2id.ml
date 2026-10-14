open! Core

(* Field order is read by position in argon2_stubs.c. *)
type costs =
  { iterations : int
  ; memory_kib : int
  ; parallelism : int
  ; hash_length : int
  }
[@@warning "-69"]

external raw
  :  string
  -> string
  -> string
  -> string
  -> costs
  -> string
  = "auth_kit_argon2id_raw"

let derive
  ?(secret_key = "")
  ?(associated_data = "")
  (p : Auth_kit.Password_hash.Argon2id.t)
  ~salt
  ~password
  =
  let costs =
    { iterations = p.iterations
    ; memory_kib = p.memory_kib
    ; parallelism = p.parallelism
    ; hash_length = p.hash_length
    }
  in
  Or_error.try_with (fun () -> raw password salt secret_key associated_data costs)
  |> Or_error.tag ~tag:"argon2id"
;;
