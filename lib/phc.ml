open! Core

module B64 = struct
  let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

  let encode s =
    let n = String.length s in
    let buf = Buffer.create (((n * 4) + 2) / 3) in
    let byte i = Char.to_int s.[i] in
    let emit v = Buffer.add_char buf alphabet.[v land 63] in
    let rec go i =
      let left = n - i in
      if left >= 3
      then (
        let v = (byte i lsl 16) lor (byte (i + 1) lsl 8) lor byte (i + 2) in
        emit (v lsr 18);
        emit (v lsr 12);
        emit (v lsr 6);
        emit v;
        go (i + 3))
      else if left = 2
      then (
        let v = (byte i lsl 16) lor (byte (i + 1) lsl 8) in
        emit (v lsr 18);
        emit (v lsr 12);
        emit (v lsr 6))
      else if left = 1
      then (
        let v = byte i lsl 16 in
        emit (v lsr 18);
        emit (v lsr 12))
    in
    go 0;
    Buffer.contents buf
  ;;

  let value c =
    match c with
    | 'A' .. 'Z' -> Some (Char.to_int c - Char.to_int 'A')
    | 'a' .. 'z' -> Some (Char.to_int c - Char.to_int 'a' + 26)
    | '0' .. '9' -> Some (Char.to_int c - Char.to_int '0' + 52)
    | '+' -> Some 62
    | '/' -> Some 63
    | _ -> None
  ;;

  let decode s =
    let n = String.length s in
    if n % 4 = 1
    then Or_error.error_string "base64: impossible length"
    else (
      match String.to_list s |> List.map ~f:value |> Option.all with
      | None -> Or_error.error_string "base64: character outside the alphabet"
      | Some vs ->
        let vs = Array.of_list vs in
        let buf = Buffer.create (n * 3 / 4) in
        let add v = Buffer.add_char buf (Char.of_int_exn (v land 255)) in
        let rec go i =
          let left = n - i in
          if left >= 4
          then (
            let v =
              (vs.(i) lsl 18)
              lor (vs.(i + 1) lsl 12)
              lor (vs.(i + 2) lsl 6)
              lor vs.(i + 3)
            in
            add (v lsr 16);
            add (v lsr 8);
            add v;
            go (i + 4))
          else if left = 3
          then (
            let v = (vs.(i) lsl 18) lor (vs.(i + 1) lsl 12) lor (vs.(i + 2) lsl 6) in
            add (v lsr 16);
            add (v lsr 8);
            v land 0xff = 0)
          else if left = 2
          then (
            let v = (vs.(i) lsl 18) lor (vs.(i + 1) lsl 12) in
            add (v lsr 16);
            v land 0xffff = 0)
          else true
        in
        (* Unused low bits must be zero, so every byte string has exactly one encoding and
           two different stored strings never decode to the same hash. *)
        if go 0
        then Ok (Buffer.contents buf)
        else Or_error.error_string "base64: non-canonical trailing bits")
  ;;
end

type t =
  { id : string
  ; version : int option
  ; params : (string * string) list
  ; salt : string
  ; hash : string
  }
[@@deriving sexp_of, compare, equal]

let valid_id s =
  let n = String.length s in
  n >= 1
  && n <= 32
  && String.for_all s ~f:(fun c ->
    Char.is_lowercase c || Char.is_digit c || Char.equal c '-')
;;

let valid_name = valid_id

let valid_value s =
  (not (String.is_empty s))
  && String.for_all s ~f:(fun c ->
    Char.is_alphanum c || List.mem [ '/'; '+'; '.'; '-' ] c ~equal:Char.equal)
;;

let param t name = List.Assoc.find t.params name ~equal:String.equal

let to_string t =
  let params =
    String.concat ~sep:"," (List.map t.params ~f:(fun (k, v) -> k ^ "=" ^ v))
  in
  String.concat
    (List.filter_opt
       [ Some ("$" ^ t.id)
       ; Option.map t.version ~f:(sprintf "$v=%d")
       ; Some ("$" ^ params)
       ; Some ("$" ^ B64.encode t.salt)
       ; Some ("$" ^ B64.encode t.hash)
       ])
;;

let parse_params s =
  String.split s ~on:','
  |> List.map ~f:(fun kv ->
    match String.lsplit2 kv ~on:'=' with
    | Some (k, v) when valid_name k && valid_value v -> Ok (k, v)
    | _ -> Or_error.error_s [%message "PHC: bad parameter" kv])
  |> Or_error.all
;;

let decode_field what s =
  if String.is_empty s
  then Or_error.error_s [%message "PHC: empty field" what]
  else Or_error.tag (B64.decode s) ~tag:what
;;

let of_string s =
  let open Or_error.Let_syntax in
  match String.split s ~on:'$' with
  | "" :: id :: rest when valid_id id ->
    let version_of v =
      match String.chop_prefix v ~prefix:"v=" with
      | Some n when (not (String.is_empty n)) && String.for_all n ~f:Char.is_digit ->
        (match Int.of_string_opt n with
         | Some n -> Ok n
         | None -> Or_error.error_string "PHC: bad version")
      | _ -> Or_error.error_string "PHC: bad version"
    in
    let%bind version, rest =
      match rest with
      | v :: (_ :: _ :: _ :: _ as rest) when String.is_prefix v ~prefix:"v=" ->
        let%map v = version_of v in
        Some v, rest
      | rest -> Ok (None, rest)
    in
    (match rest with
     | [ params; salt; hash ] ->
       let%bind params = parse_params params in
       let%bind salt = decode_field "salt" salt in
       let%map hash = decode_field "hash" hash in
       { id; version; params; salt; hash }
     | _ -> Or_error.error_string "PHC: expected $id[$v=n]$params$salt$hash")
  | _ -> Or_error.error_string "PHC: bad algorithm id"
;;
