open Core.Std
open Async.Std

let static_handler ?content_type filename = fun _ _ _ ->
  let headers = match content_type with
    | None -> None
    | Some(typ) ->
      Some(Cohttp.Header.init_with "Content-type" typ) in
  Cohttp_async.Server.respond_with_file ?headers filename

let string_handler str = fun _ _ _ ->
  Cohttp_async.Server.respond_with_string str

let not_found_handler = fun _ _ _ ->
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
  let edge_to_json (l: Topo.edge) = `String "()" in
  let vertices = `List (Topo.VertexSet.fold (Topo.vertexes t)
      ~f: (fun acc v -> (vertex_to_json (Topo.vertex_to_label t v))::acc)
      ~init: []) in
  (* TODO: edge json *)
  let edges = `List [] in
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
        fun _ _ _ ->
          Cohttp_async.Server.respond_with_string ~code:(`Code 404)
            "Not found" in
  fun ~body addr request ->
    (loop (Uri.path (Cohttp.Request.uri request)) table) body addr request

let create ?max_connections ?max_pending_connections
    ?buffer_age_limit ?on_handler_error routes =
  Cohttp_async.Server.create ?max_connections ?max_pending_connections
    ?buffer_age_limit ?on_handler_error
    (Tcp.on_port 8080) (routes_to_handler routes)
