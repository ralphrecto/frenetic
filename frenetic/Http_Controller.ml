open Core.Std
open Async.Std
open Cohttp_async
open NetKAT_Types
open Common
module Server = Cohttp_async.Server

type client = {
  (* Write new policies to this node *)
  policy_node: (DynGraph.cannot_receive, policy) DynGraph.t;
  (* Read from this pipe to send events *)
  event_reader: event Pipe.Reader.t;
  (* Write to this pipe when new event received from the network *)
  event_writer: event Pipe.Writer.t
}

let unions (pols : policy list) : policy =
  List.fold_left pols ~init:drop ~f:(fun p q -> Union (p, q))

let pol : (policy, policy) DynGraph.t = DynGraph.create drop unions

let clients : (string, client) Hashtbl.t = Hashtbl.Poly.create ()

let iter_clients (f : string -> client -> unit) : unit =
  Hashtbl.iter clients ~f:(fun ~key ~data -> f key data)

(* Gets the client's node in the dataflow graph, or creates it if doesn't exist *)
let get_client (clientId: string): client =
  Hashtbl.find_or_add clients clientId
     ~default:(fun () ->
               printf ~level:`Info "New client %s" clientId;
               let node = DynGraph.create_source drop in
               DynGraph.attach node pol;
               let (r, w) = Pipe.create () in
               { policy_node = node; event_reader = r; event_writer =  w})

let handle_request
  (event : unit -> event Deferred.t)
  (send_packet_out : switchId -> SDN_Types.pktOut -> unit Deferred.t)
  (query : string -> (Int64.t * Int64.t) Deferred.t)
  ~(body : Cohttp_async.Body.t)
  (client_addr : Socket.Address.Inet.t)
  (request : Request.t) : Server.response Deferred.t =
  match request.meth, extract_path request with
    | `GET, ["query"; name] ->
      printf "GET /query/%s" name;
      query name
      >>= fun stats ->
      Server.respond_with_string (NetKAT_Json.stats_to_json_string stats)
    | `GET, [clientId; "event"] ->
      printf "GET /event";
      event ()
      >>= fun evt ->
      Server.respond_with_string (NetKAT_Json.event_to_json_string evt)
    | `POST, ["pkt_out"] ->
      handle_parse_errors body
        (fun body ->
           Body.to_string body >>= fun str ->
           let json = Yojson.Basic.from_string str in
           return (NetKAT_SDN_Json.pkt_out_from_json json))
        (fun (sw_id, pkt_out) ->
           printf "POST /pkt_out";
           send_packet_out sw_id pkt_out
           >>= fun () ->
           Cohttp_async.Server.respond `OK)
    | `POST, [clientId; "update_json"] ->
      printf "POST /%s/update_json" clientId;
      handle_parse_errors body parse_update_json
      (fun pol ->
         DynGraph.push pol (get_client clientId).policy_node;
         Cohttp_async.Server.respond `OK)
    | `POST, [clientId; "update" ] ->
      printf "POST /%s/update" clientId;
      handle_parse_errors body parse_update
      (fun pol ->
         DynGraph.push pol (get_client clientId).policy_node;
         Cohttp_async.Server.respond `OK)
    | _, _ -> printf "Got garbage from Client"; Cohttp_async.Server.respond `Not_found


(* Run embedded HTTP server *)
let routes = [
  ("/topology", fun _ ->
    (* TODO: get the actual topology instead of empty *)
      Gui_Server.string_handler "{}");
  ("/switch/([1-9][0-9]*)", fun g ->
      let sw_id = Int64.of_string (Array.get g 1) in
      printf "Requested policy for switch %Lu" sw_id;
      let pol = NetKAT_Types.drop in
      Gui_Server.string_handler (NetKAT_Pretty.string_of_policy pol))
]

let listen ~port =
  Async_OpenFlow.OpenFlow0x01.Controller.create ~port:6633 ()
  >>= fun controller ->
  let module Controller = NetKAT_Controller.Make (struct
      let controller = controller
    end) in
  let _ = Cohttp_async.Server.create (Tcp.on_port port)
    (handle_request Controller.event Controller.send_packet_out Controller.query) in
  let _ = Gui_Server.create (routes @ Gui_Server.routes) in
  let (_, pol_reader) = DynGraph.to_pipe pol in
  let _ = Pipe.iter pol_reader ~f:(fun pol -> Controller.update_policy pol) in
  Controller.start ();
  Deferred.return ()

let main (args : string list) : unit = match args with
  | [ "--app-port"; p ] | [ "-a"; p ] ->
    don't_wait_for (listen ~port:(Int.of_string p))
  | [] -> don't_wait_for (listen ~port:9000)
  |  _ -> (print_endline "Invalid command-line arguments"; Shutdown.shutdown 1)


