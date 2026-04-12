
//        0                   1                   2                   3
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |V=2|P|X|  CC   |M|     PT      |       sequence number         |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                           timestamp                           |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |           synchronization source (SSRC) identifier            |
//       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
//       |            contributing source (CSRC) identifiers             |
//       |                             ....                              |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


Rtp_Header_Flags    ::  enum  u16  {
  VERSION           ::  0b10  <<   14;
  PADDING           ::  0b1   <<   13;
  EXTENSION         ::  0b1   <<   12;
  MARKER_BIT        ::  0b1   <<    7;
};

RtpHeader :: struct {
  flags: u16 = cast(u16)Rtp_Header_Flags.VERSION;
  seq_no: u16;
  timestamp: u32;
  ssrc: u32;
  // csrc: u32; // we can actually have 15 max
} #no_padding;

RtpSender :: struct {
  n_packets: u16;
  ssrc: u32;
  csrc: u32;
  socket: Socket;
};
rtp_header_set_payload_type :: (header: *RtpHeader, type: u8) {
  assert(type <= 0x7f);
  header.flags |= type;
}

rtp_header_set_csrc_count :: (header: *RtpHeader, count: u8) {
  assert(count <= 0xf);
  header.flags |= count << 8;
}

rtp_header_set_flag :: (header: *RtpHeader, flag: Rtp_Header_Flags) {
  header.flags |= cast(u16)flag;
}

rtp_header_print :: (header: *RtpHeader) -> string #expand {
  return tprint("{\n  flags: %b,\n  seq_no: %,\n  timestamp: %\n  ssrc: %,\n  csrc: %,\n}\n", formatInt(header.flags, base = 2), header.seq_no, header.timestamp, header.ssrc, header.csrc);
}


rtp_sender_new :: (ip: string, port: u16) -> RtpSender {
  SSRC :: 0xDB157006;

  servaddr: sockaddr_in;
  servaddr.sin_addr.s_addr = inet_addr(to_c_string(ip));
  servaddr.sin_port = htons(port);
  servaddr.sin_family = AF_INET;

  sockfd := socket(AF_INET, .SOCK_DGRAM, 0);

  if connect(sockfd, cast(*sockaddr)*servaddr, size_of(type_of(servaddr))) < 0 {
      log_err("error: failed to set address to sockfd\n");
      assert(false); // this can never fail
  }

  return .{
    n_packets = 0,
    ssrc = SSRC,
    csrc = 0,
    socket = xx sockfd,
  };
}


write_rtp :: (using ctx: *RtpSender, nalu: []u8, timestamp: u32) {
  packet_len := nalu.count + size_of(RtpHeader);
  if packet_len > 0xffff {
    // split into FU-A
    assert(false, "unimplemented!");
  }

  RTP_HEADER_LENGTH :: size_of(RtpHeader);
  n_packets += 1;
  rtp_header: RtpHeader = .{
    seq_no =  htons(n_packets),
    timestamp = htonl(timestamp),
    ssrc = htonl(ssrc),
  };
  rtp_header_set_payload_type(*rtp_header, 96);
  rtp_header.flags = htons(rtp_header.flags);

  serialized :[..]u8;  // TODO(shahzad): @leak
  array_reserve(*serialized, packet_len);

  memcpy(serialized.data, xx *rtp_header, RTP_HEADER_LENGTH);
  memcpy(serialized.data + RTP_HEADER_LENGTH , nalu.data, nalu.count);

  bytes_written := send(xx socket, serialized.data, xx packet_len, 0);
  assert(bytes_written != -1);
  assert(bytes_written == packet_len);
}

#scope_file
#import "Basic";
#import "Socket";
#import "POSIX";
#import "Log";
