The reference Argon2id hash of "password" with salt "somesalt":

  $ H='$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc'
  $ auth-kit inspect "$H"
  (Argon2id
   ((memory_kib 65536) (iterations 2) (parallelism 1) (salt_length 8)
    (hash_length 32)))
Correct, but new hashes get a 16-byte salt, so the tool asks for a rehash even at the
same memory cost:

  $ echo password | auth-kit verify -m 65536 "$H"
  match_rehash
  $ echo password | auth-kit verify "$H"
  match_rehash
  $ echo wrong | auth-kit verify "$H"
  mismatch
  [1]

Hashes made by the tool verify:

  $ H2=$(echo 120587 | auth-kit hash -m 64 -t 1)
  $ echo 120587 | auth-kit verify -m 64 -t 1 "$H2"
  match

Passcode rules:

  $ echo 120587 | auth-kit check-passcode
  ok
  $ echo 000000 | auth-kit check-passcode
  all_same
  [1]
  $ echo 12a | auth-kit check-passcode
  too_short
  not_digits
  [1]
