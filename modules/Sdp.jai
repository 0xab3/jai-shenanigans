ANSWER_DC_ONLY :: "v=0\r\no=- 2508192892581753534 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\na=extmap-allow-mixed\r\na=msid-semantic: WMS\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=ice-ufrag:MuJd\r\na=ice-pwd:M7tLfiCRCC7WR8iTB+kEpoKD\r\na=ice-options:trickle\r\na=fingerprint:sha-256 F2:A0:D4:5D:E5:E2:47:BE:02:B4:F2:A8:CE:AD:6F:5E:64:45:EA:9D:21:34:2E:3C:63:C9:6D:F0:3A:CA:1B:5E\r\na=setup:active\r\na=mid:0\r\na=sctp-port:5000\r\na=max-message-size:262144\r\n";
ANSWER_AS_JSON_DC_ONLY :: #string END_ANSWER
{"sdp":"v=0\r\no=- 2508192892581753534 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\na=extmap-allow-mixed\r\na=msid-semantic: WMS\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=ice-ufrag:MuJd\r\na=ice-pwd:M7tLfiCRCC7WR8iTB+kEpoKD\r\na=ice-options:trickle\r\na=fingerprint:sha-256 F2:A0:D4:5D:E5:E2:47:BE:02:B4:F2:A8:CE:AD:6F:5E:64:45:EA:9D:21:34:2E:3C:63:C9:6D:F0:3A:CA:1B:5E\r\na=setup:passive\r\na=mid:0\r\na=sctp-port:5000\r\na=max-message-size:262144\r\n","type":"answer"}
END_ANSWER

Session_Level_Section :: struct {
  version: u32;
  originator: string;
  session_name: string;
  time_description: string; // we don't care right now
  attributes: [..]string;

  ice_ufrag: string; // should not be here but shoved it anyways for convinience we will remove it later
  ice_pwd: string;
};

Media_Description :: struct {
  name: string;
  connection: string;

  attributes: [..]string; // attributes we couldn't parse

  // attributes
  send_recv: bool = false;
  setup: string;
  mid: u32;
  sctp_port: u32;
  max_message_size: u64;
  ice_ufrag: string;
  ice_pwd: string;
};
Session_Description :: struct {
  sls: Session_Level_Section;
  mds: [..]Media_Description;
};

SDP_Parsing_State :: enum {
  PARSING_SLS;
  PARSING_MD;

};
SDP_Parse_Error :: enum {
  Success;
  MalformedSDP;
};

to_string :: (sdp: Session_Description) -> string {
  assert(false, "unimplemented!");
}

parse_sdp :: (sdp_as_str: string) -> Session_Description, SDP_Parse_Error {
  sdp := Session_Description.{};
  md := Media_Description.{};
  state := SDP_Parsing_State.PARSING_SLS;
  ok, left, right := split_from_left_by_any(sdp_as_str, "\r\n");
  while ok {
    defer {ok, left, right = split_from_left_by_any(right, "\r\n");}
    if left.count == 0 continue;
    left = trim(left);
    assert(left[1] == #char "=");

    key := left[0];
    value := copy_string(trim_right(slice(left, 2, left.count)));

    if left[0] == {
      case #char "v"; {
        as_int, ok := to_integer(value);
        if !ok return .{}, .MalformedSDP;
        sdp.sls.version = xx as_int;
        assert(sdp.sls.version == 0);
      }
      case #char "o"; sdp.sls.originator = value;
      case #char "s"; sdp.sls.session_name = value;
      case #char "t"; sdp.sls.time_description = value;
      case #char "c"; {
        assert(state == .PARSING_MD, "SLS also have c key but we do not handle it so panicking!");
        md.connection = value;
      }
      case #char "a"; {
        if state == .PARSING_SLS {
          array_add(*sdp.sls.attributes, value);
          continue;
        }

        found, _attrib_name, _attrib_value := split_from_left(value, ":");
        attrib_name := trim(_attrib_name);
        attrib_value := copy_string(trim_right(_attrib_value));

        if !found {
          if equal(value, "sendrecv") md.send_recv = true;
          else assert(false, tprint("unknown attribute % with no value\n", attrib_name));
        }

        if equal(attrib_name, "setup") md.setup = attrib_value;
        else if equal(attrib_name, "mid") md.mid = xx to_integer(attrib_value);
        else if equal(attrib_name, "sctp-port") md.mid = xx to_integer(attrib_value);
        else if equal(attrib_name, "max-message-size") md.max_message_size = xx to_integer(attrib_value);
        else if equal(attrib_name, "ice-ufrag") {
          md.ice_ufrag = attrib_value;
          sdp.sls.ice_ufrag = attrib_value;
        }
        else if equal(attrib_name, "ice-pwd") {
        md.ice_pwd = attrib_value;
        sdp.sls.ice_pwd = attrib_value;
        }
      }
      case #char "m"; {
        // previous media description is filled meaning we have to push it
        if md.name.count != 0 array_add(*sdp.mds, md);
        md = .{};
        md.name = value;
        state = .PARSING_MD;
      }
    }

  }
  return sdp, .Success;
}

#import "String";
#import "Basic";
