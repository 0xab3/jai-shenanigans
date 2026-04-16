Peer_Connection :: struct (T: Type) {
  On_Ice_Candidate :: #type (pc: *Peer_Connection(T), candidate: *Ice_Candidate, udata: *T);
  config: Peer_Configuration;
  check_list: Check_List;
  local_candidates: [..]Ice_Candidate;
  remote_candidates: [..]Ice_Candidate;

  local_description: Session_Description;
  remote_description: Session_Description;
  on_ice_candidate: On_Ice_Candidate;
  storage: Temporary_Storage;
  dtls_ctx: DTLS_Context;
  udata: T;
};

Peer_Configuration :: struct {
  ice_config: Ice_Configuration;
};

check_list_add :: (list: *Check_List, pair: Ice_Candidate_Pair) {
  // @todo implement https://datatracker.ietf.org/doc/html/rfc8445#section-6.1.2
  array_add(*list.pairs, pair);
}

// @remove this shit has to go
add_local_candidates :: (pc: *Peer_Connection($T), candidates: ..Ice_Candidate)
{
  array_add(*pc.local_candidates, ..candidates);
  for candidates {
    if pc.on_ice_candidate pc.on_ice_candidate(pc, *it, *pc.udata);
  }
}

on_ice_candidate :: (pc: *Peer_Connection($T), cb: Peer_Connection(T).On_Ice_Candidate) {
  pc.on_ice_candidate = cb;

  for pc.local_candidates pc.on_ice_candidate(pc, *it, *pc.udata);
}

add_ice_candidate :: (pc: *Peer_Connection($T), candidate: Ice_Candidate) {
  array_add(*pc.remote_candidates, candidate);
  remote := *pc.remote_candidates.data[pc.remote_candidates.count - 1];

  for * pc.local_candidates {
    if can_pair(it, remote) check_list_add(*pc.check_list, .{ it, remote, false });
  }
}
new_peer_connection :: (config: Peer_Configuration, udata: $T) -> Peer_Connection(T) {
  pc: Peer_Connection(T) = .{
    config = config,
    udata = udata,
  };
  return pc;

}

create_offer :: (pc: *Peer_Connection) {
  assert(false, "stub!");
}

create_answer :: (pc: *Peer_Connection) {
  assert(false, "stub!");
}

set_local_description :: (pc: *Peer_Connection($T), sdp: Session_Description) {
  pc.local_description = sdp;
}

set_remote_description :: (pc: *Peer_Connection($T), sdp: Session_Description) {
  pc.remote_description = sdp;
}

get_local_ice_ufrag :: (pc: Peer_Connection($T)) -> string {
  assert(pc.local_description.sls.ice_ufrag.count != 0, "local description is probably not set!");
  return pc.local_description.sls.ice_ufrag;
}

get_local_ice_pwd :: (pc: Peer_Connection($T)) -> string {
  assert(pc.local_description.sls.ice_pwd.count != 0, "local description is probably not set!");
  return pc.local_description.sls.ice_pwd;
}

gather_local_candidates :: (pc: *Peer_Connection($T)) {
  // @todo this should only be triggered when we add a new componenet
  candidates: [..]Ice_Candidate;
  candidates.allocator = temp;
  host_candidates := get_host_candidates(*candidates);
  // NOTE: @important srflx/relay candidates will do a read call from network that is bloacking
  // figure out the architecture for that, we can put the request in io_uring, on response we can
  // parse the response and have a reference to peer connection in it
  // (and put it in the type of the candidate??? idk how we will do that tho)
  // add_local_candidates(pc, ..host_candidates);
  add_local_candidates(pc, ..host_candidates);
}

#scope_file
#import "ICE";
#import "Basic";
#import "Sdp";
#import "DTLS";
