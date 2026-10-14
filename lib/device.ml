open! Core

module Ip_prefix = struct
  type t = string [@@deriving sexp, compare, equal]

  let to_string t = t

  let ipv4_octets s =
    match String.split s ~on:'.' with
    | [ _; _; _; _ ] as parts ->
      List.map parts ~f:(fun p ->
        if String.length p >= 1
           && String.length p <= 3
           && String.for_all p ~f:Char.is_digit
           && Int.of_string p <= 255
        then Some (Int.of_string p)
        else None)
      |> Option.all
    | _ -> None
  ;;

  (* The groups of one side of a "::" (or of the whole address), as 16-bit numbers; a
     dotted IPv4 tail counts as two groups. *)
  let groups part =
    let hex g =
      if String.length g >= 1
         && String.length g <= 4
         && String.for_all g ~f:Char.is_hex_digit
      then Some (Int.of_string ("0x" ^ g))
      else None
    in
    let rec go = function
      | [] -> Some []
      | [ last ] when String.mem last '.' ->
        (match ipv4_octets last with
         | Some [ a; b; c; d ] -> Some [ (a lsl 8) lor b; (c lsl 8) lor d ]
         | _ -> None)
      | g :: rest -> Option.both (hex g) (go rest) |> Option.map ~f:(fun (g, r) -> g :: r)
    in
    if String.is_empty part then Some [] else go (String.split part ~on:':')
  ;;

  let ipv6_groups s =
    let s = Option.value_map (String.lsplit2 s ~on:'%') ~default:s ~f:fst in
    match String.substr_index_all s ~may_overlap:false ~pattern:"::" with
    | [] -> Option.filter (groups s) ~f:(fun g -> List.length g = 8)
    | [ i ] ->
      let head = String.prefix s i
      and tail = String.drop_prefix s (i + 2) in
      if String.mem head '.'
      then None
      else (
        match groups head, groups tail with
        | Some h, Some t when List.length h + List.length t <= 7 ->
          Some (h @ List.init (8 - List.length h - List.length t) ~f:(Fn.const 0) @ t)
        | _ -> None)
    | _ -> None
  ;;

  let of_address s =
    match ipv4_octets s with
    | Some (a :: b :: _) -> Some (sprintf "%d.%d" a b)
    | Some _ -> None
    | None ->
      (match ipv6_groups s with
       (* ::ffff:a.b.c.d is an IPv4 client seen through a dual-stack socket. *)
       | Some [ 0; 0; 0; 0; 0; 0xffff; hi; _ ] ->
         Some (sprintf "%d.%d" (hi lsr 8) (hi land 0xff))
       | Some (g0 :: g1 :: g2 :: _) -> Some (sprintf "%x:%x:%x" g0 g1 g2)
       | Some _ | None -> None)
  ;;
end

module Stable = struct
  module V1 = struct
    type t =
      { id : string
      ; user_agent : string option
      ; ip_prefix : string option
      ; signed_in_at : Time_ns.Stable.Alternate_sexp.V1.t
      ; last_active_at : Time_ns.Stable.Alternate_sexp.V1.t option
      ; expires_at : Time_ns.Stable.Alternate_sexp.V1.t
      ; signed_out_at : Time_ns.Stable.Alternate_sexp.V1.t option
      }
    [@@deriving bin_io, sexp, compare, equal]
  end
end

type t = Stable.V1.t =
  { id : string
  ; user_agent : string option
  ; ip_prefix : Ip_prefix.t option
  ; signed_in_at : Time_ns.t
  ; last_active_at : Time_ns.t option
  ; expires_at : Time_ns.t
  ; signed_out_at : Time_ns.t option
  }
[@@deriving compare, equal]

let sexp_of_t = Stable.V1.sexp_of_t

let create ~id ?user_agent ?ip_address ~now ~lifetime () =
  { id
  ; user_agent = Option.map user_agent ~f:(fun ua -> String.prefix ua 512)
  ; ip_prefix = Option.bind ip_address ~f:Ip_prefix.of_address
  ; signed_in_at = now
  ; last_active_at = None
  ; expires_at = Time_ns.add now lifetime
  ; signed_out_at = None
  }
;;

let is_active t ~now = Option.is_none t.signed_out_at && Time_ns.( < ) now t.expires_at

let touch ?(every = Time_ns.Span.of_int_min 5) t ~now =
  if not (is_active t ~now)
  then None
  else (
    match t.last_active_at with
    | Some last when Time_ns.Span.( < ) (Time_ns.diff now last) every -> None
    | _ -> Some { t with last_active_at = Some now })
;;

let sign_out t ~now =
  match t.signed_out_at with
  | Some _ -> t
  | None -> { t with signed_out_at = Some now }
;;

module View = struct
  type device = t [@@deriving sexp_of, compare, equal]

  type t =
    { device : device
    ; current : bool
    }
  [@@deriving sexp_of, compare, equal]
end

let last_seen t = Option.value t.last_active_at ~default:t.signed_in_at

let list devices ~current ~now =
  List.filter devices ~f:(is_active ~now)
  |> List.map ~f:(fun d -> { View.device = d; current = String.equal d.id current })
  |> List.sort ~compare:(fun (a : View.t) (b : View.t) ->
    match Bool.compare b.current a.current with
    | 0 ->
      (match Time_ns.compare (last_seen b.device) (last_seen a.device) with
       | 0 -> String.compare a.device.id b.device.id
       | c -> c)
    | c -> c)
;;

let sign_out_one devices ~id ~current ~now =
  match List.find devices ~f:(fun d -> String.equal d.id id && is_active d ~now) with
  | None -> devices, None
  | Some _ ->
    ( List.map devices ~f:(fun d -> if String.equal d.id id then sign_out d ~now else d)
    , Some
        (Security_log.Kind.Device_signed_out
           { device = id; this_device = String.equal id current }) )
;;

let sign_out_others devices ~current ~now =
  let count = ref 0 in
  let devices =
    List.map devices ~f:(fun d ->
      if (not (String.equal d.id current)) && is_active d ~now
      then (
        incr count;
        sign_out d ~now)
      else d)
  in
  devices, !count, Security_log.Kind.Other_devices_signed_out { count = !count }
;;
