(lang dune 3.17)

(name auth-kit)

(generate_opam_files true)

(license MIT)

(maintainers "hello@winterchill.xyz")

(authors "WinterChill AI")

(source
 (github winterchill-trading/auth-kit))

(homepage "https://github.com/winterchill-trading/auth-kit")

(bug_reports "https://github.com/winterchill-trading/auth-kit/issues")

(documentation "https://github.com/winterchill-trading/auth-kit#readme")

(package
 (name auth-kit)
 (synopsis "Passcodes, lockout, devices and a security log for account security")
 (description
  "auth-kit holds the account-security rules a consumer finance service needs around sign-in: passcode strength rules, Argon2id hashing in self-describing PHC strings (with PBKDF2-SHA256 verification for migrating older hashes), progressive lockout after wrong attempts, a reset hook for out-of-band codes, device records with sign-out and last-seen, an append-only security log with stable event kinds, idle auto-lock settings, and the decision logic around step-up grants. The rules are pure values and functions; nothing is persisted. The hashing sub-library binds the reference libargon2.")
 (tags
  (security passcode argon2 lockout authentication))
 (depends
  (ocaml
   (>= 5.2.0))
  dune
  (dune-configurator
   (>= 3.0))
  conf-pkg-config
  (core
   (and
    (>= v0.17.0)
    (< v0.19~)))
  (ppx_jane
   (and
    (>= v0.17.0)
    (< v0.19~)))
  (cryptokit
   (>= 1.16))
  (async
   (and
    :with-test
    (>= v0.17.0)
    (< v0.19~)))
  (service-kit :with-test)
  (odoc :with-doc)))
