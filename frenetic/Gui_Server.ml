open Core.Std
open Async.Std

type handler = body:Cohttp_async.Body.t -> Unix.Socket.Address.Inet.t -> 
  Cohttp_async.Request.t -> Cohttp_async.Server.response Deferred.t

type routes = (bytes * (bytes array -> handler)) list

let static_handler ?content_type (filename: bytes) = fun ~body _ _ ->
  let headers = match content_type with
    | None -> None
    | Some(typ) ->
      Some(Cohttp.Header.init_with "Content-type" typ) in
  Cohttp_async.Server.respond_with_file ?headers filename

let bytes_handler (b: bytes) : handler = fun ~body _ _ ->
  Cohttp_async.Server.respond_with_string "hi"

let string_handler str : handler = fun ~body _ _ ->
  Cohttp_async.Server.respond_with_string str

let not_found_handler : handler = fun ~body _ _ ->
  Cohttp_async.Server.respond_with_string ~code:(`Code 404) "Not found"

let topo_to_json (t: Async_NetKAT.Net.Topology.t) =
  let module Topo = Async_NetKAT.Net.Topology in
  let vertex_to_json (v: Async_NetKAT.node): Yojson.Safe.json =
    match v with
    | Switch s_id -> 
        `Assoc [("type", `String "switch"); 
                ("id", `Intlit (Int64.to_string s_id))]
    | Host (dladdr, nwaddr) ->
        `Assoc [("type", `String "host");
                ("mac", `String (Packet.string_of_mac dladdr));
                ("ip", `String (Packet.string_of_ip nwaddr))] in

  let edge_to_json (e: Topo.edge) nodes = 
    let vlist = Yojson.Basic.Util.to_list (Yojson.Safe.to_basic nodes) in 
    let src, src_port = Topo.edge_src e in
    let dst, dst_port = Topo.edge_dst e in 
    let src = Topo.vertex_to_label t src in 
    let dst = Topo.vertex_to_label t dst in  

    let rec find_index el lst acc= 
	match lst with
	| [] -> -1
	| hd::tl -> if (hd = el) then acc
		    else find_index el tl acc+1 in

    let src_id = find_index (Yojson.Safe.to_basic (vertex_to_json src)) vlist 0 in 
    let dst_id = find_index (Yojson.Safe.to_basic (vertex_to_json dst)) vlist 0 in 
    `Assoc [("src_id", `Int src_id);
            ("src_port", `Int (Int32.to_int_exn src_port));
            ("label", `String "");
            ("dst_id", `Int dst_id);
            ("dst_port", `Int (Int32.to_int_exn dst_port))] in
  let vertices = `List (Topo.VertexSet.fold (Topo.vertexes t)
      ~f: (fun acc v -> (vertex_to_json (Topo.vertex_to_label t v))::acc)
      ~init: []) in
  let edges = `List (Topo.fold_edges (fun e acc -> (edge_to_json e vertices)::acc) t []) in
  Yojson.Safe.to_string (`Assoc [("nodes", vertices); ("links", edges);])

let routes = [
  ("/",
    fun _ -> static_handler "static/index.html");
  (* XXX(seliopou): These are very, very bad patterns for a route, as they
   * espose the entire filesystem. It'll do for a demo. *)
  ("/static/(.*\\.svg)",
    fun g ->
        static_handler ~content_type:"image/svg+xml" ("static/" ^ (Array.get g 1)));
  ("/static/(.*)",
    fun g ->
        static_handler ("static/" ^ (Array.get g 1)))
]

let routes_to_handler rs =
  let table = List.map rs ~f:(fun (route, handler) ->
    printf "Compiled \"%s\"" route;
    (Re_posix.(compile (re ("^" ^ route ^ "$"))), handler)) in
  let rec loop uri t =
    match t with
      | (re, handler)::t' ->
        begin try handler Re.(get_all (exec re uri))
          with Not_found -> loop uri t'
        end
      | [] ->
        fun ~body _ _ ->
          Cohttp_async.Server.respond_with_string ~code:(`Code 404)
            "Not found" in
  fun ~body addr (request: Cohttp.Request.t) ->
    (loop (Uri.path (Cohttp.Request.uri request)) table) body addr request

let create ?max_connections ?max_pending_connections
    ?buffer_age_limit ?on_handler_error ext_routes =
  Cohttp_async.Server.create ?max_connections ?max_pending_connections
    ?buffer_age_limit ?on_handler_error
    (Tcp.on_port 8080) (routes_to_handler (routes @ ext_routes))
