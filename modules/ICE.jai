ICE_FOUNDATION :: "403992139";

RTP_COMPONENT_ID :: 1;
RCTP_COMPONENT_ID :: 2;

// @unused add sm comptime bs here so we can directly get the field out of this
ICE_SUPPORTED_EXTENSIONS :: string.["generation", "ufrag", "network-cost"];

// @scope generated in SDP but we hard code it for now
UFRAG :: "MuJd";
UPWD :: "M7tLfiCRCC7WR8iTB+kEpoKD";
ICE_OPTION :: "trickle"; // trickle
// https://datatracker.ietf.org/doc/html/rfc8839#section-5.1-4.10
// data streams based on RTP, candidates for the actual RTP media MUST have a component ID of 1
// and candidates for RTCP MUST have a component ID of 2.


Ice_Configuration :: struct {
  // TODO(shahzad): @feat implement parsing of stun server's string
  stun_servers: []Network_Endpoint;
  turn_servers: []Network_Endpoint;
};

Ice_Candidate_Pair :: struct {
  local: *Ice_Candidate;
  remote: *Ice_Candidate;
  conn: Socket_Connection;

  is_connected := false;

};

Ice_Candidate :: struct {
  Kind :: enum {HOST; SRFLX; PRFLX; RELAY;};
  Transport_Kind :: enum {UDP; TCP;}; // always udp in our case
  foundation: string; // from 9-32 ice-chars (ALPHA / DIGIT / "+" / "/")
  componenet_id: u8; // 1-256 (ik we are missing 1 but we are not having 200+ components in our stream)
  transport: Transport_Kind; //
  priority: u32; // 1 - 1*10 digits
  connection_addr: string; // we can have mdns addresses here (for privacy :sob:)
  port: u16;
  candidate_type: Kind;

  // https://datatracker.ietf.org/doc/html/rfc8839#section-5.1-4.16
  // <rel_addr> and <rel_port> MUST be present for server-reflexive, peer-reflexive, and relayed candidates
  rel_addr: Ip_Address; // NOTE(shahzad): @important not present in HOST for some reason
  rel_port: u16;
  ufrag: string;
  network_cost: u16; // 0-999 "cost" of taking the network, lower is better
                    // (chromium defines wifi to be 0 and 5g to be 250 or smth idk)

  family: Ip_Family;

  // @remove this is a part of json not "Ice_Candidate"
  sdp_mid: string;
  sdp_mline_index: u32;

  // @remove ts has to go
  sock: Socket;

};

Check_List :: struct {
  State :: enum {
    RUNNING;
    COMPLETED;
    FAILED;
  }
  pairs: [..]Ice_Candidate_Pair;
  tid_lut: Table(
    Stun_Transaction_Id, *Ice_Candidate_Pair,
    given_compare_function = transaction_id_eq,
    given_hash_function = transaction_id_hash,
  );
  state: State = .RUNNING;
};

Valid_List :: struct {
  candidates: [..]*Ice_Candidate;
};

can_pair :: (c1: *Ice_Candidate, c2: *Ice_Candidate) -> bool {
  return c1.componenet_id == c2.componenet_id && c1.transport == c2.transport;
}


compute_ice_priority :: () {
 // https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.2.1
 assert(false, "unimplemented");
}
ice_parser_get_token :: (ice_string: string, is_ip: bool) -> tok:string,rest:string {
  assert(!is_ip, "unimplemented");
}

parse_ice_candidate_string :: (ice_string: string) -> Ice_Candidate {
  ice_string_view := ice_string;
  _, ok := parse_token(*ice_string_view, delimiters = ":");
  assert(ok);
  // skip the colon
  ice_string_view = xx array_view(cast([]u8)ice_string_view, 1);

  raddr: string = "0.0.0.0";
  rport: u16 = 0;

  // @todo @priority remove all assertions as the string we get is from network
  foundation:,       ok  =  parse_token(*ice_string_view);  assert(ok);
  componenet_id:,    ok  =  parse_int(*ice_string_view);    assert(ok);
  transport:,        ok  =  parse_token(*ice_string_view);  assert(ok);
  priority:,         ok  =  parse_int(*ice_string_view);    assert(ok);
  connection_addr:,  ok  =  parse_token(*ice_string_view);  assert(ok);
  port:,             ok  =  parse_int(*ice_string_view);    assert(ok);
  _,                 ok  =  parse_token(*ice_string_view);  assert(ok);
  candidate_type:,   ok  =  parse_token(*ice_string_view);  assert(ok);

  cand_type := ice_candidate_type_from_string(candidate_type);

  if cand_type != .HOST {
    _,      ok  =  parse_token(*ice_string_view);  assert(ok);
    raddr,  ok  =  parse_token(*ice_string_view);  assert(ok);
    _,      ok  =  parse_token(*ice_string_view);  assert(ok);

    rport_as_str:,  ok  =  parse_token(*ice_string_view); assert(ok);
    if !equal(rport_as_str, "0")
      rport, ok = xx string_to_int(rport_as_str); assert(ok);
  }
  transport_type: Ice_Candidate.Transport_Kind =
      ifx equal(transport, "udp") xx .UDP
      else ifx equal(transport, "tcp") xx .TCP else { assert(false); xx .TCP;};

  candidate := Ice_Candidate.{
    foundation = foundation,
    componenet_id = xx componenet_id,
    transport = transport_type,
    priority = xx priority,
    connection_addr = connection_addr,
    port = xx port,
    candidate_type = cand_type,
    rel_addr = ip_addr_from_string(raddr),
    rel_port = xx rport,
  };

  // @scope now we are have to parse extensions there should be an array of some sort that hold the supported
  // extension that we can loop on and parse all that now we are just hard coding it

  while ice_string_view.count > 0 {
    token:,  ok  =  parse_token(*ice_string_view); if !ok break;
    value:,  ok  =  parse_token(*ice_string_view, ";=(),\""); if !ok break;
    if equal(token, "generation") {}
    else if equal(token, "ufrag") {
      candidate.ufrag = value;
    }
    else if equal(token, "network-cost") {
      candidate.network_cost, ok = xx parse_int(*value);
    }
  }
  return candidate;
}
new_ice_candidate :: (addr: Socket_Address, type: Ice_Candidate.Kind, component_id: u8) -> Ice_Candidate {
  candidate: Ice_Candidate;
  candidate = .{
    foundation = ICE_FOUNDATION,
    componenet_id = component_id,
    transport = .UDP,
    priority = 0xffff,
    connection_addr = to_string(addr.addr),
    port = addr.port,
    candidate_type = type,
    rel_addr = Ip_Address.{},
    rel_port = 0,
    ufrag = UFRAG,
    network_cost = 999,
    sdp_mid = "0",
    sdp_mline_index = 0,

  };
  return candidate;
}

ice_candidate_type_from_string :: (as_str: string) -> Ice_Candidate.Kind {
  if equal(as_str, "host") {
    return .HOST;
  }else if equal(as_str, "srflx") {
    return .SRFLX;
  }else if equal(as_str, "prflx") {
    return .PRFLX;
  }else if equal(as_str, "relay") {
    return .RELAY;
  }else {
    assert(false, "unreachable"); return .HOST;
  }
  assert(false, "unreachable"); return .HOST;
}
to_string :: (typ: Ice_Candidate.Kind) -> string {
  if typ == {
    case .HOST;
      return "host";
    case .SRFLX;
      return "srflx";
    case .PRFLX;
      return "prflx";
    case .RELAY;
      return "relay";
    case;
    assert(false, tprint("unidentified type %!\n", typ));
    return ""; // :sob: have a no return in you language bro :sob:
  }
  return "";
}

to_string :: (typ: Ice_Candidate.Transport_Kind) -> string {
  if typ == {
    case .UDP;
      return "udp";
    case .TCP;
      return "tcp";
    case;
      assert(false, tprint("unidentified type %!\n", typ));
      return "";
  }
  return "";
}

to_string :: (builder: *String_Builder, using candidate: *Ice_Candidate) -> string {
// "candidate:1165362036 1 udp 1677729535 117.223.196.177 45852 typ srflx raddr 0.0.0.0 rport 0 generation 0 ufrag E89D network-cost 999"
  rel_addr_and_port := "";
  if candidate_type != .HOST {
    rel_addr_and_port = tprint("raddr % rport % ", to_string(rel_addr), rel_port);
  }

  // @need_context does generation 0 make any difference??
  ok := print_to_builder(builder,
  // all of the shit after typ and rel addr is extension
    "candidate:% % % % % % typ % %ufrag % network-cost %", foundation,
      componenet_id, to_string(transport), priority, connection_addr, port,
      to_string(candidate_type), rel_addr_and_port, ufrag, network_cost,
  );
  assert(ok);
  return builder_to_string(builder);
}


// the whole json thing
// @remove this should be at the edge of our program not in the middle or should it?
to_chrome_ice_candidate_shit :: (builder: *String_Builder, using candidate :*Ice_Candidate) -> string {
  // {"candidate":"candidate:1165362036 1 udp 1677729535 117.223.196.177 45852 typ srflx raddr 0.0.0.0 rport 0 generation 0 ufrag E89D network-cost 999","sdpMid":"0","sdpMLineIndex":0,"usernameFragment":"E89D"}

  rel_addr_and_port := "";
  if candidate_type != .HOST {
    rel_addr_and_port = tprint("raddr % rport % ", to_string(rel_addr), rel_port);
  }

  // @need_context does generation 0 make any difference??
  ok := print_to_builder(builder,
  // all of the shit after typ and rel addr is extension
    "{\"candidate\": \"candidate:% % % % % % typ % %ufrag % network-cost %\",\"sdpMid\":\"%\",\"sdpMLineIndex\":%,\"usernameFragment\":\"%\"}",
      foundation, componenet_id, to_string(transport), priority, connection_addr, port,
      to_string(candidate_type), rel_addr_and_port, ufrag, network_cost, sdp_mid, sdp_mline_index, ufrag
  );
  assert(ok);
  return builder_to_string(builder);
}

get_host_candidates :: (candidates: *[..]Ice_Candidate) -> []Ice_Candidate {
  iter: *ifaddrs;
  getifaddrs(*iter);

  mark := candidates.count;
  component_id := RTP_COMPONENT_ID; // @scope @priority make this not be hardcoded
  RANDOM_PORT :: 4264; // random port that i chose for no reason

  sock_fd := xx socket(AF_INET, .DGRAM, xx 0);
  assert(sock_fd > 2);
  while iter != null {
    defer iter = iter.ifa_next;
    // we only support IPV4
    if iter.ifa_addr && iter.ifa_addr.sa_family == AF_INET {
      p_addr: *sockaddr_in = cast(*sockaddr_in)iter.ifa_addr;
      ip_addr := p_addr.sin_addr.s_addr;

      // @need_context idk why we have to do byte swap for this
      if BYTE_SWAP(ip_addr) == INADDR_LOOPBACK continue;

      ret := bind(cast(Socket)sock_fd, BYTE_SWAP(ip_addr), RANDOM_PORT);
      if ret != 0 {
        print("addr is this %\n", to_string(p_addr));
        assert(ret == 0);
      }
      // @useless we are not supporting ipv6 anyways
      family: Ip_Family =
        ifx p_addr.sin_family == AF_INET then .IPV4
        else ifx p_addr.sin_family == AF_INET6 then .IPV6
        else { assert(false); .IPV4;};

      as_sock_addr := Socket_Address.{
        addr = Ip_Address.{ family, ip_addr },
        port = RANDOM_PORT,
      };
      ice_candidate := new_ice_candidate(as_sock_addr, .HOST, xx component_id);
      ice_candidate.sock = sock_fd;
      

      array_add(candidates, ice_candidate);
    }
  }
  freeifaddrs(iter);

  return array_view(candidates.*, mark, candidates.count);
}


// @incomplete
get_reflexive_candidates :: (using candidates: []Ice_Candidate) {
  server := config.stun_servers[0];
  info := stun_server_info_from_network_endpoint(server);
  response := send_binding_request(*info);

  ok: bool; ip_info_attr: Socket_Address;
  ok, ip_info_attr = stun_message_try_get_mapped_address(response);
}
get_relay_candidates :: () {
  assert(false, "unimplemented! we don't support turn for now");
}

get_random_string :: (len: u64) -> string #expand {
  new_len := (len + 3) / 4 * 3;
  as_string := talloc_string(new_len);
  random_bytes(*as_string);
  base64_encoded := base64_encode(as_string);
  assert(len <= base64_encoded.count, "we pkd up");
  base64_encoded.count = len;
  return base64_encoded;
}


#scope_file
#import "Stun";
#import "Socket";
#import "String";
#import "Basic";
#import "Hash_Table";
#import "Net";
#import "Random";
#import "Base64";
#import "POSIX";
#import "utils";


// SDP_NO_TRICKLE

// v=0
// o=- 6917409782085055512 2 IN IP4 127.0.0.1
// s=-
// t=0 0
// a=group:BUNDLE 0
// a=extmap-allow-mixed
// a=msid-semantic: WMS
// m=application 56129 UDP/DTLS/SCTP webrtc-datachannel
// c=IN IP4 117.223.196.177
// a=candidate:770584261 1 udp 2113937151 6fe34fa9-0681-49d9-8d9c-d614430bcd17.local 56129 typ host generation 0 network-cost 999
// a=candidate:619222051 1 udp 1677729535 117.223.196.177 56129 typ srflx raddr 0.0.0.0 rport 0 generation 0 network-cost 999
// a=ice-ufrag:aKmq
// a=ice-pwd:lLriuxMTA+/b37hhClsCdGYh
// a=ice-options:trickle
// a=fingerprint:sha-256 2A:65:ED:FE:6F:A7:31:23:8F:80:42:89:44:6A:26:26:35:ED:10:B3:3A:7E:C5:2E:82:94:BD:5D:83:D3:45:56
// a=setup:actpass
// a=mid:0
// a=sctp-port:5000
// a=max-message-size:262144
