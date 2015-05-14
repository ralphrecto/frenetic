open NetKAT_Types
open Async.Std

type t

val port_stats : t -> switchId -> portId -> OpenFlow0x01_Stats.portStats Deferred.t

val current_switches : t -> (switchId * portId list) list Deferred.t

val query : t -> string -> (Int64.t * Int64.t) Deferred.t option
(* app name -> event deferred *)
val event : t -> string -> string Deferred.t

val pkt_out : t -> switchId -> SDN_Types.pktOut -> unit Deferred.t
(* app name -> policy -> unit *)
val update : t -> string -> NetKAT_Types.policy -> unit Deferred.t

val start : int -> int -> unit -> unit
