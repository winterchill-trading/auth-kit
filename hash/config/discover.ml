(* Finds libargon2 through pkg-config (Debian/Ubuntu libargon2-dev, Homebrew argon2),
   falling back to plain -largon2 when pkg-config does not know it. *)

module C = Configurator.V1

let () =
  C.main ~name:"libargon2" (fun c ->
    let default : C.Pkg_config.package_conf = { libs = [ "-largon2" ]; cflags = [] } in
    let conf =
      match C.Pkg_config.get c with
      | None -> default
      | Some pc ->
        (match C.Pkg_config.query pc ~package:"libargon2" with
         | None -> default
         | Some conf -> conf)
    in
    C.Flags.write_sexp "c_flags.sexp" conf.cflags;
    C.Flags.write_sexp "c_library_flags.sexp" conf.libs)
;;
