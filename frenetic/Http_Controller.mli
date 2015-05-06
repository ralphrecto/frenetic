
open NetKAT_Types
open Async.Std

val port_stats : switchId -> SDN_Types.pktOut -> OpenFlow0x01_Stats.portStats Deferred.t

val current_switches : unit -> (switchId * portId list) list

val query : string -> (Int64.t * Int64.t) Deferred.t

(* app name -> event deferred *)
val event : string -> NetKAT_Types.event Deferred.t

val pkt_out : switchId -> SDN_Types.pktOut -> unit Deferred.t

(* app name -> policy -> unit *)
val update : string -> NetKAT_Types.policy -> unit

val start : int -> int -> unit -> unit
