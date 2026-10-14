open! Core

module Argon2id = struct
  type t =
    { memory_kib : int
    ; iterations : int
    ; parallelism : int
    ; salt_length : int
    ; hash_length : int
    }
  [@@deriving sexp, compare, equal]

  let default =
    { memory_kib = 19456
    ; iterations = 2
    ; parallelism = 1
    ; salt_length = 16
    ; hash_length = 32
    }
  ;;
end

module Pbkdf2_sha256 = struct
  type t =
    { iterations : int
    ; salt_length : int
    ; hash_length : int
    }
  [@@deriving sexp, compare, equal]
end

module Scheme = struct
  type t =
    | Argon2id of Argon2id.t
    | Pbkdf2_sha256 of Pbkdf2_sha256.t
  [@@deriving sexp, compare, equal]

  let id = function
    | Argon2id _ -> "argon2id"
    | Pbkdf2_sha256 _ -> "pbkdf2-sha256"
  ;;
end

module Limits = struct
  type t =
    { max_memory_kib : int
    ; max_iterations : int
    ; max_parallelism : int
    ; max_pbkdf2_iterations : int
    ; min_salt_length : int
    ; min_hash_length : int
    ; max_length : int
    }
  [@@deriving sexp, compare, equal]

  let default =
    { max_memory_kib = 1 lsl 20
    ; max_iterations = 64
    ; max_parallelism = 16
    ; max_pbkdf2_iterations = 10_000_000
    ; min_salt_length = 8
    ; min_hash_length = 16
    ; max_length = 64
    }
  ;;

  let check t (scheme : Scheme.t) =
    let in_range what v ~lo ~hi =
      if v >= lo && v <= hi
      then Ok ()
      else
        Or_error.error_s
          [%message "hash cost out of range" what (v : int) (lo : int) (hi : int)]
    in
    let lengths ~salt_length ~hash_length =
      [ in_range "salt length" salt_length ~lo:t.min_salt_length ~hi:t.max_length
      ; in_range "hash length" hash_length ~lo:t.min_hash_length ~hi:t.max_length
      ]
    in
    Or_error.combine_errors_unit
      (match scheme with
       | Argon2id p ->
         [ in_range "parallelism" p.parallelism ~lo:1 ~hi:t.max_parallelism
         ; in_range "iterations" p.iterations ~lo:1 ~hi:t.max_iterations
           (* RFC 9106: m >= 8p. *)
         ; in_range "memory" p.memory_kib ~lo:(8 * p.parallelism) ~hi:t.max_memory_kib
         ]
         @ lengths ~salt_length:p.salt_length ~hash_length:p.hash_length
       | Pbkdf2_sha256 p ->
         in_range "iterations" p.iterations ~lo:1 ~hi:t.max_pbkdf2_iterations
         :: lengths ~salt_length:p.salt_length ~hash_length:p.hash_length)
  ;;
end

type t =
  { scheme : Scheme.t
  ; salt : string
  ; hash : string
  }
[@@deriving sexp_of, compare, equal]

let to_string t =
  let int = Int.to_string in
  let phc : Phc.t =
    match t.scheme with
    | Argon2id p ->
      { id = "argon2id"
      ; version = Some 0x13
      ; params = [ "m", int p.memory_kib; "t", int p.iterations; "p", int p.parallelism ]
      ; salt = t.salt
      ; hash = t.hash
      }
    | Pbkdf2_sha256 p ->
      { id = "pbkdf2-sha256"
      ; version = None
      ; params = [ "i", int p.iterations ]
      ; salt = t.salt
      ; hash = t.hash
      }
  in
  Phc.to_string phc
;;

let int_param (phc : Phc.t) name =
  match Phc.param phc name with
  | None -> Or_error.error_s [%message "missing parameter" name]
  | Some v ->
    (match Int.of_string_opt v with
     | Some n when String.for_all v ~f:Char.is_digit -> Ok n
     | _ -> Or_error.error_s [%message "bad parameter" name v])
;;

let of_phc (phc : Phc.t) =
  let open Or_error.Let_syntax in
  let salt_length = String.length phc.salt
  and hash_length = String.length phc.hash in
  let only names =
    match
      List.find phc.params ~f:(fun (k, _) -> not (List.mem names k ~equal:String.equal))
    with
    | None -> Ok ()
    | Some (k, _) -> Or_error.error_s [%message "unknown parameter" k]
  in
  let%map scheme =
    match phc.id, phc.version with
    | "argon2id", Some 0x13 ->
      let%bind () = only [ "m"; "t"; "p" ] in
      let%map memory_kib = int_param phc "m"
      and iterations = int_param phc "t"
      and parallelism = int_param phc "p" in
      Scheme.Argon2id { memory_kib; iterations; parallelism; salt_length; hash_length }
    | "argon2id", v ->
      Or_error.error_s [%message "unsupported Argon2 version" (v : int option)]
    | "pbkdf2-sha256", None ->
      let%bind () = only [ "i" ] in
      let%map iterations = int_param phc "i" in
      Scheme.Pbkdf2_sha256 { iterations; salt_length; hash_length }
    | id, _ -> Or_error.error_s [%message "unsupported scheme" id]
  in
  { scheme; salt = phc.salt; hash = phc.hash }
;;

let of_hex s =
  let n = String.length s in
  if n = 0 || n % 2 = 1 || not (String.for_all s ~f:Char.is_hex_digit_lower)
  then Or_error.error_string "bad hex"
  else
    Ok
      (String.init (n / 2) ~f:(fun i ->
         Char.of_int_exn (Int.of_string ("0x" ^ String.sub s ~pos:(2 * i) ~len:2))))
;;

(* The hex form written by services that hashed with PBKDF2 before adopting PHC strings:
   [pbkdf2-sha256$<iterations>$<salt hex>$<hash hex>], no leading '$'. *)
let of_legacy_hex s =
  let open Or_error.Let_syntax in
  match String.split s ~on:'$' with
  | [ "pbkdf2-sha256"; iterations; salt; hash ] ->
    let%bind iterations =
      match Int.of_string_opt iterations with
      | Some n when String.for_all iterations ~f:Char.is_digit -> Ok n
      | _ -> Or_error.error_string "bad iteration count"
    in
    let%bind salt = of_hex salt in
    let%map hash = of_hex hash in
    { scheme =
        Pbkdf2_sha256
          { iterations
          ; salt_length = String.length salt
          ; hash_length = String.length hash
          }
    ; salt
    ; hash
    }
  | _ -> Or_error.error_string "unrecognised hash format"
;;

let of_string ?(limits = Limits.default) s =
  let open Or_error.Let_syntax in
  let%bind t =
    if String.is_prefix s ~prefix:"$"
    then Phc.of_string s |> Or_error.bind ~f:of_phc
    else of_legacy_hex s
  in
  let%map () = Limits.check limits t.scheme in
  t
;;

let constant_time_equal a b =
  String.length a = String.length b
  &&
  let acc = ref 0 in
  for i = 0 to String.length a - 1 do
    acc := !acc lor (Char.to_int a.[i] lxor Char.to_int b.[i])
  done;
  !acc = 0
;;

let lengths : Scheme.t -> int * int = function
  | Argon2id p -> p.salt_length, p.hash_length
  | Pbkdf2_sha256 p -> p.salt_length, p.hash_length
;;

module Hasher = struct
  type nonrec t =
    { target : Scheme.t
    ; limits : Limits.t
    ; derive : Scheme.t -> salt:string -> secret:string -> string Or_error.t
    ; random : int -> string
    }

  let create ?(limits = Limits.default) ~target ~derive ~random () =
    Limits.check limits target |> Or_error.ok_exn;
    { target; limits; derive; random }
  ;;

  let target t = t.target
  let limits t = t.limits

  let with_target t target =
    Limits.check t.limits target |> Or_error.ok_exn;
    { t with target }
  ;;

  let derive t scheme ~salt ~secret =
    let open Or_error.Let_syntax in
    let _, hash_length = lengths scheme in
    let%bind hash = t.derive scheme ~salt ~secret in
    if String.length hash = hash_length
    then Ok hash
    else
      Or_error.error_s
        [%message
          "derivation returned the wrong length"
            (hash_length : int)
            ~got:(String.length hash : int)]
  ;;

  let hash t secret =
    let open Or_error.Let_syntax in
    let salt_length, _ = lengths t.target in
    let salt = t.random salt_length in
    let%map hash = derive t t.target ~salt ~secret in
    { scheme = t.target; salt; hash }
  ;;
end

module Verification = struct
  type t =
    | Mismatch
    | Match
    | Match_rehash
  [@@deriving sexp, compare, equal, enumerate]

  let is_match = function
    | Mismatch -> false
    | Match | Match_rehash -> true
  ;;
end

let needs_rehash hasher t = not (Scheme.equal t.scheme (Hasher.target hasher))

let verify hasher t secret =
  let open Or_error.Let_syntax in
  let%map derived = Hasher.derive hasher t.scheme ~salt:t.salt ~secret in
  if not (constant_time_equal derived t.hash)
  then Verification.Mismatch
  else if needs_rehash hasher t
  then Match_rehash
  else Match
;;

module Stable = struct
  module V1 = struct
    type nonrec t = t

    include Sexpable.Of_stringable (struct
        type nonrec t = t

        let to_string = to_string
        let of_string s = of_string s |> Or_error.ok_exn
      end)

    include Binable.Of_stringable_with_uuid (struct
        type nonrec t = t

        let to_string = to_string
        let of_string s = of_string s |> Or_error.ok_exn

        let caller_identity =
          Bin_prot.Shape.Uuid.of_string "5d0c2e7a-3b8f-4f6e-a1c9-7e2d4b6f8a31"
        ;;
      end)

    let compare = compare
    let equal = equal
  end
end
