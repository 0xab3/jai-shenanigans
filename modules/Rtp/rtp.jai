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

RTP_Header :: struct {
  flags: u16 = cast(u16)Rtp_Header_Flags.VERSION;
  seq_no: u16;
  timestamp: u32;
  ssrc: u32;
  // csrc: u32; // we can actually have 15 max
} #no_padding;

RTP_Packet :: struct {
  using #as header: RTP_Header;
  payload: []u8;
};

RTP_Sender :: struct {
  n_packets: u16;
  ssrc: u32;
  csrc: u32;
  conn: Socket_Connection;
};

rtp_header_set_payload_type :: (header: *RTP_Header, type: u8) {
  assert(type <= 0x7f);
  header.flags |= type;
}

rtp_header_set_csrc_count :: (header: *RTP_Header, count: u8) {
  assert(count <= 0xf);
  header.flags |= count << 8;
}

rtp_header_set_flag :: (header: *RTP_Header, flag: Rtp_Header_Flags) {
  header.flags |= cast(u16)flag;
}

rtp_header_print :: (header: *RTP_Header) -> string #expand {
  return tprint("{\n  flags: %b,\n  seq_no: %,\n  timestamp: %\n  ssrc: %,\n  csrc: %,\n}\n", formatInt(header.flags, base = 2), header.seq_no, header.timestamp, header.ssrc, header.csrc);
}


// @unused
rtp_sender_new :: (conn: Socket_Connection) -> RTP_Sender {
  SSRC :: 3477136883;

  return .{
    n_packets = 0,
    ssrc = SSRC,
    csrc = 0,
    conn = conn,
  };
}

rtp_packet_new :: (ctx: *RTP_Sender, nalu: []u8, timestamp: u32) -> RTP_Packet {
  packet_len := nalu.count + size_of(RTP_Header);
  if packet_len > 0xffff {
    // split into FU-A
    assert(false, "unimplemented!");
  }

  ctx.n_packets += 1;
  rtp_header: RTP_Header = .{
    seq_no =  htons(ctx.n_packets),
    timestamp = htonl(timestamp),
    ssrc = htonl(ctx.ssrc),
  };
  rtp_header_set_payload_type(*rtp_header, 96);
  rtp_header.flags = htons(rtp_header.flags);

  return .{ rtp_header, nalu };
}

write_rtp :: (using ctx: *RTP_Sender, nalu: []u8, timestamp: u32) {
  packet_len := nalu.count + size_of(RTP_Header);
  if packet_len > 0xffff {
    // split into FU-A
    assert(false, "unimplemented!");
  }

  RTP_HEADER_LENGTH :: size_of(RTP_Header);
  n_packets += 1;
  rtp_header: RTP_Header = .{
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

  bytes_written := send(xx conn.sock, serialized.data, xx packet_len, 0);
  assert(bytes_written != -1);
  assert(bytes_written == packet_len);
}

#scope_file
#import "Basic";
#import "Socket";
#import "POSIX";
#import "Log";
#import "Net";
