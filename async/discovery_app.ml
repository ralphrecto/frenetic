open Core.Std
open Async.Std

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

  let update ((nib, evt): Net.Topology.t *  NetKAT_Types.event) =
    let open Net.Topology in
    match evt with
      (*
      | LinkUp of switch_port * switch_port (* how to handle LinkUp/LinkDown? *)
      | LinkDown of switch_port * switch_port
      | HostUp of switch_port * host
      | HostDown of switch_port * host
      | PacketIn ("probe", switch, port, payload, len) ->
          let open Packet in
          begin match parse (SDN_Types.payload_bytes payload) with
          | { nw = Unparsable (dlTyp, bytes) } when dlTyp = Probe.protocol ->
      *)

      | SwitchUp (switch, ports) ->
          let nib', node = add_vertex nib switch in
          let nib'' = List.fold ports ~init:nib'
            ~f:(fun nib'' port -> add_port nib'' node port) in
      | SwitchDown switch ->
          remove_vertex nib (vertex_of_label (Switch switch)), []
      | PortUp (switch, port) ->
          add_port nib (vertex_of_label (Switch switch)) port, []
      | PortDown of switch_port
          remove_port nib (vertex_of_label (Switch switch)) port, []
      | _ -> nib * []

end

module Host = struct

  let update ((nib, evt): Net.Topology.t *  NetKAT_Types.event) : Net.Topology.t = nib

end

module Discovery = struct

  type t = {
    nib : Net.Topology.t ref;
  }

  let t = { nib = ref Net.Topology.empty }

  let rec loop (event_pipe: NetKAT_Types.event Pipe.Reader.t) : unit Deferred.t =
    Pipe.read >>| function
      | `Eof -> ()
      | `Ok evt -> 
          t.nib := !t.nib, evt |> Switch.update |> Host.update;
          loop event_pipe

  let start (event_pipe: NetKAT_Types.event Pipe.Reader.t) : t = 
    let open NetKAT_Types in
    let policy =
      let probe 
    don't_wait_for (loop event_pipe);
    t

end
