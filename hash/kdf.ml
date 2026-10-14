open! Core
module Password_hash = Auth_kit.Password_hash

let derive (scheme : Password_hash.Scheme.t) ~salt ~secret =
  match scheme with
  | Argon2id p -> Argon2id.derive p ~salt ~password:secret
  | Pbkdf2_sha256 p ->
    Or_error.try_with (fun () ->
      Pbkdf2_sha256.derive
        ~iterations:p.iterations
        ~length:p.hash_length
        ~salt
        ~password:secret)
;;

let random n = Cryptokit.Random.string Cryptokit.Random.secure_rng n

let hasher
  ?limits
  ?(target = Password_hash.Scheme.Argon2id Password_hash.Argon2id.default)
  ()
  =
  Password_hash.Hasher.create ?limits ~target ~derive ~random ()
;;
