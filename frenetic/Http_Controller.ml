open Core.Std
open Async.Std
open Cohttp_async
open NetKAT_Types
open Common
module Server = Cohttp_async.Server
module Log = Async_OpenFlow.Log

type client = {
  (* Write new policies to this node *)
  policy_node: (DynGraph.cannot_receive, policy) DynGraph.t;
  (* Read from this pipe to send events *)
  event_reader: string Pipe.Reader.t;
  (* Write to this pipe when new event received from the network *)
  event_writer: string Pipe.Writer.t;
}

(* TODO(arjun):

  <facepalm>

  These are OpenFlow 1.0 types. Everywhere else, we are using SDN_Types. *)
let port_to_json port = `Int (Int32.to_int_exn port)

let switch_and_ports_to_json (sw, ports) =
  `Assoc [("switch_id", `Int (Int64.to_int_exn sw));
          ("ports", `List (List.map ~f:port_to_json ports))]

let current_switches_to_json lst =
  `List (List.map ~f:switch_and_ports_to_json lst)

let current_switches_to_json_string lst =
  Yojson.Basic.to_string ~std:true (current_switches_to_json lst)
(* </facepalm> *)

let unions (pols : policy list) : policy =
  List.fold_left pols ~init:drop ~f:(fun p q -> Union (p, q))

let pol : (policy, policy) DynGraph.t = DynGraph.create drop unions

let clients : (string, client) Hashtbl.t = Hashtbl.Poly.create ()

let iter_clients (f : string -> client -> unit) : unit =
  Hashtbl.iter clients ~f:(fun ~key ~data -> f key data)

let rec propogate_events event =
  event () >>=
  fun evt ->
  let response = NetKAT_Json.event_to_json_string evt in
  (* TODO(jcollard): Is there a mapM equivalent here? *)
  Hashtbl.iter clients (fun ~key ~data:client ->
    Pipe.write_without_pushback client.event_writer response);
  propogate_events event

(* Gets the client's node in the dataflow graph, or creates it if doesn't exist *)
let get_client (clientId: string): client =
  Hashtbl.find_or_add clients clientId
     ~default:(fun () ->
               printf ~level:`Info "New client %s" clientId;
               let node = DynGraph.create_source drop in
               DynGraph.attach node pol;
         let (r, w) = Pipe.create () in
               { policy_node = node; event_reader = r; event_writer =  w })

type t = (module NetKAT_Controller.CONTROLLER)

let port_stats (t : t) = 
  let module Controller = (val t) in Controller.port_stats 

let current_switches (t : t) =
  let module Controller = (val t) in
  Controller.current_switches () |> return

let query (t : t) name =
  let module Controller = (val t) in
  if (Controller.is_query name) then Some (Controller.query name)
  else None

let event (t : t) clientId =
  let module Controller = (val t) in
  (get_client clientId).event_reader |> Pipe.read >>| function
    | `Eof -> assert false
    | `Ok response -> response

let pkt_out (t : t) =
  let module Controller = (val t) in Controller.send_packet_out

let update _  clientId pol =
  DynGraph.push pol (get_client clientId).policy_node |> return

let handle_request (t : t)
  ~(body : Cohttp_async.Body.t)
  (client_addr : Socket.Address.Inet.t)
  (request : Request.t) : Server.response Deferred.t =
  let module Controller = (val t) in
  Log.info "%s %s" (Cohttp.Code.string_of_method request.meth)
    (Uri.path request.uri);
  match request.meth, extract_path request with
    | `GET, ["version"] -> Server.respond_with_string "3"
    | `GET, ["port_stats"; switch_id; port_id] ->
       ((port_stats t) (Int64.of_string switch_id) (Int32.of_string port_id) >>|
       NetKAT_Json.port_stats_to_json_string) >>= Server.respond_with_string
    | `GET, ["current_switches"] ->
      current_switches t >>| current_switches_to_json_string >>= Server.respond_with_string
    | `GET, ["query"; name] ->
      begin query t name |> function
        | Some x -> x >>| NetKAT_Json.stats_to_json_string >>= Server.respond_with_string
        | None -> Log.info "query %s is not defined in the current policy" name;
            let headers = Cohttp.Header.init_with "X-Query-Not-Defined" "true" in
            Server.respond_with_string ~headers
            (NetKAT_Json.stats_to_json_string (0L, 0L)) end
    | `GET, [clientId; "event"] -> event t clientId >>= Server.respond_with_string
    | `POST, ["pkt_out"] ->
      handle_parse_errors' body
        (fun str ->
           str |> Yojson.Basic.from_string |> NetKAT_SDN_Json.pkt_out_from_json)
        (fun (sw_id, pkt) ->
           ((pkt_out t) sw_id pkt) >>= fun _ ->
           Cohttp_async.Server.respond `OK)
    | `POST, [clientId; "update_json"] ->
      handle_parse_errors body parse_update_json
      (fun pol ->
         DynGraph.push pol (get_client clientId).policy_node;
         Cohttp_async.Server.respond `OK)
    | `POST, [clientId; "update" ] ->
      handle_parse_errors body parse_update
      (fun pol -> update t clientId pol >>= fun _ -> Cohttp_async.Server.respond `OK)
    | _, _ ->
      Log.error "Unknown method/path (404 error)";
      Cohttp_async.Server.respond `Not_found

let print_error addr exn =
  Log.error "%s" (Exn.to_string exn)

let start (http_port : int) (openflow_port : int) () : unit = 
  let _ = Async_OpenFlow.OpenFlow0x01.Controller.create ~port:openflow_port ()
  >>= fun controller ->
  let module Controller = NetKAT_Controller.Make (struct
      let controller = controller
    end) in
  let on_handler_error = `Call print_error in
  let _ = Cohttp_async.Server.create
    ~on_handler_error
    (Tcp.on_port http_port)
    (handle_request (module Controller)) in
  let (_, pol_reader) = DynGraph.to_pipe pol in
  let _ = Pipe.iter pol_reader ~f:(fun pol -> Controller.update_policy pol) in
  Controller.start ();
  let t : t = (module Controller) in

  let node_data_string pol flowtable = begin
    let open Yojson.Basic.Util in 
    let polstr = NetKAT_Pretty.string_of_policy pol in 
    let flow_json = Yojson.Basic.to_string(NetKAT_SDN_Json.flowTable_to_json flowtable) in 
    Yojson.Basic.to_string (`Assoc[("policy",`String polstr);
		      ("flowtable",`String flow_json)])
    end  in

  (* initialize discovery *)
  let discoverclient = get_client "discover" in
  let discover =
    let event_pipe = Pipe.map discoverclient.event_reader
      ~f:(fun s -> s |> Yojson.Basic.from_string |> NetKAT_Json.event_from_json) in
    Discoveryapp.Discovery.start event_pipe (pkt_out t) in
  update t "discover" discover.policy >>| fun _ ->
  let routes = [
    ("/topology", fun _ ->
      Gui_Server.string_handler (Gui_Server.topo_to_json !(discover.nib)));
    ("/switch/([1-9][0-9]*)", fun g ->
        let sw_id = Int64.of_string (Array.get g 1) in
        printf "Requested policy for switch %Lu" sw_id;
        let pol = discover.policy in
	let flow_table = List.fold_left (Controller.get_table sw_id) ~f:(fun acc x -> (fst x) :: acc) ~init:[] in
        Gui_Server.string_handler (node_data_string pol flow_table))
  ] in
  let _ = Gui_Server.create routes in
  don't_wait_for (propogate_events Controller.event) in
  ()
