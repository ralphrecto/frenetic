open Core.Std
open Async.Std
open NetKAT_Types

let guard (pred: pred) (policy: policy) =
  Seq(Filter pred, policy)

module Net = Async_NetKAT.Net

module Switch = struct
  module Probe = struct
    cstruct probe_payload {
      uint64_t switch_id;
      uint32_t port_id
    } as big_endian

    (* XXX(seliopou): Watch out for this. The protocol in etheret packets has two
     * different meanings depending on the range of values that it falls into. If
     * anything weird happens with probe sizes, look here.  This is not the protocol,
     * but in fact the size.  *)

    let protocol = 0x05ff
    let mac = 0xffeabbadabbaL

    exception Wrong_type

    (* A probe consists of a switch_id and port_id, both represented as int64s
     * regardless of the underlying OpenFlow protocol's representation.
     * [rjjr: info is from the switch to which probe was originally sent] *)
    type t =
      { switch_id : int64
      ; port_id : int32
      }

    let marshal t b =
      set_probe_payload_switch_id b t.switch_id;
      set_probe_payload_port_id b t.port_id;
      sizeof_probe_payload

    let marshal' t =
      let b = Cstruct.create sizeof_probe_payload in
      ignore (marshal t b);
      b

    let parse b =
      { switch_id = get_probe_payload_switch_id b
      ; port_id = get_probe_payload_port_id b
      }

    let of_packet p =
      let open Packet in
      match p.nw with
        | Unparsable(proto, b)
          when proto = protocol -> parse b
        | _ -> raise Wrong_type

    let to_packet t =
      let open Packet in
      { dlSrc = mac
      ; dlDst = 0xffffffffffffL
      ; dlVlan = None
      ; dlVlanDei = false
      ; dlVlanPcp = 0x0
      ; nw = Unparsable(protocol, marshal' t)
      }
  end

  let probes = ref []

  let probe_period = Time.Span.of_sec 3.0

  let send_probes () =
    let uri = Uri.of_string "http://localhost:8080/pkt_out" in
    Cohttp_async.Client.post 

  let handle_probe nib dst_swid dst_port (probe : Probe.t) : Net.Topology.t =
    let open Net.Topology in
    let open Async_NetKAT in
    let topo, v1 = add_vertex nib (Switch dst_swid) in
    let topo, v2 = add_vertex topo (Switch probe.switch_id) in
    let topo, _ = add_edge topo v1 dst_port () v2 probe.port_id in
    let topo, _ = add_edge topo v2 probe.port_id () v1 dst_port in
    topo

  let update (nib: Net.Topology.t) (evt: event) : Net.Topology.t =
    let open Net.Topology in
    match evt with
      | PacketIn ("probe", switch, port, payload, len) ->
          let open Packet in
          begin match parse (SDN_Types.payload_bytes payload) with
          | { nw = Unparsable (dlTyp, bytes) } when dlTyp = Probe.protocol ->
              let probe = Probe.parse bytes in
              handle_probe nib switch port probe
          | _ -> nib (* error: bad packet *)
          end
      | SwitchUp (switch, ports) ->
          let nib', node = add_vertex nib (Switch switch) in
          List.fold ports ~init:nib'
            ~f:(fun nib'' port -> add_port nib'' node port)
      | SwitchDown switch ->
          remove_vertex nib (vertex_of_label nib (Switch switch))
      | PortUp (switch_id, port_id) ->
          probes := ({switch_id; port_id} :: !probes);
          add_port nib (vertex_of_label nib (Switch switch)) port
      | PortDown (switch, port) ->
          remove_port nib (vertex_of_label nib (Switch switch)) port
      | _ -> nib

  let rec probeloop (sender : switchId -> SDN_Types.pktOut -> unit Deferred.t) =
    Clock.after probe_period >>=
      fun () ->
        Deferred.List.iter ~how:`Parallel !probes (fun probe ->
          sender switch_id (Probe.to_packet probe)) >>= 

  let create () : policy =
    guard (Test(EthSrc Probe.mac)) (Mod(Location(Pipe "probe")))

end

module Host = struct
  (*TODO: update policy when packet's destination is in known_hosts*)
  let update (nib: Net.Topology.t) (pol:policy) (evt:event) : Net.Topology.t  * policy
  	= match evt with
 	| PacketIn( _ ,sw_id,pt_id,payload,len) -> 
 		let open Packet in 
 		let dlAddr, nwAddr = match parse(SDN_Types.payload_bytes payload) with
 		| {nw = Arp (Arp.Query(dlSrc,nwSrc,_)) } 
 		| {nw = Arp (Arp.reply(dlSrc,nwSrc,_,_)) } ->
 			(dlSrc,nwSrc) 
 		| _ -> assert false in
   	  let host = try Some (vertex_of_label nib (Host(dlAddr, nwAddr))) 
   	  	with _ -> None in 
   	  begin match TUtil.in_edge nib sw_id pt_id, h with
   	  	| true, None ->
   	  	  let nib', h = add_vertex nib (Host(dlAddr,nwAddr)) in
   	  	  let nib', s = add_vertex nib' (Switch sw_id) in  (*is this line necessary?*)
   	  	  let nib', _ = add_edge nib' s pt_id () h 01 in
   	  	  let nib', _ = add_edge nib' h 01 () s pt_id in 
   	  	  let pol' = 
   	  	  (nib', pol)
   	  	| _ , _ -> (nib,pol)
   	  end

   	 | PortDown (sw_id,pt_id) -> 
   	 	let v = vertex_of_label nib (Switch sw_id) in 
   	 	let mh = next_hop nib v pt_id in 
   	 	begin match mh with 
   	 	| None -> (nib,pol)
   	 	| Some (edge) -> 
   	 		let (v2,pt_id2) = edge_dst edge in 
   	 		begin match vertex_of_label nib v2 with 
   	 			| Switch _ -> (nib,pol)
   	 			| Host (dlAddr, nwAddr) ->
   	 				(remove_endpint nib (v,pt_id), pol)
   	 		end
   	 	end

  let create (): policy =  guard (Test((EthType 0x0806)), Mod(Location(Pipe "host")))

end

module Discovery = struct

  type t = {
    nib : Net.Topology.t ref;
    policy : policy;
  }

  let t = { 
    nib = ref (Net.Topology.empty ());
    policy = id;
  }    

  let rec loop (event_pipe: event Pipe.Reader.t) : unit Deferred.t =

    Pipe.read event_pipe >>= function
      | `Eof -> return ()
      | `Ok evt -> 
          t.nib := Host.update (Switch.update !(t.nib) evt) evt;
          loop event_pipe

  let start (event_pipe: event Pipe.Reader.t)
      (module Controller : NetKAT_Controller.CONTROLLER) = 

    let policy = Union (Switch.create (), Host.create ()) in
    don't_wait_for (Deferred.both
      (loop event_pipe)
      (probeloop Controller.send_packet_out));
    {t with policy}

end
