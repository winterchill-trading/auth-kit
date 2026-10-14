open! Core

let hmac ~key msg = Cryptokit.hash_string (Cryptokit.MAC.hmac_sha256 key) msg

let xor_into acc s =
  for i = 0 to Bytes.length acc - 1 do
    Bytes.set
      acc
      i
      (Char.of_int_exn (Char.to_int (Bytes.get acc i) lxor Char.to_int s.[i]))
  done
;;

let block ~iterations ~salt ~password index =
  let be32 =
    String.init 4 ~f:(fun i -> Char.of_int_exn ((index lsr (8 * (3 - i))) land 0xff))
  in
  let u = ref (hmac ~key:password (salt ^ be32)) in
  let acc = Bytes.of_string !u in
  for _ = 2 to iterations do
    u := hmac ~key:password !u;
    xor_into acc !u
  done;
  Bytes.to_string acc
;;

let derive ~iterations ~length ~salt ~password =
  if iterations < 1 then raise_s [%message "Pbkdf2_sha256: iterations < 1"];
  if length < 1 then raise_s [%message "Pbkdf2_sha256: length < 1"];
  let blocks = (length + 31) / 32 in
  String.concat (List.init blocks ~f:(fun i -> block ~iterations ~salt ~password (i + 1)))
  |> String.sub ~pos:0 ~len:length
;;
