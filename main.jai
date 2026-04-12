#import "Basic";
#import "Compiler";
Hash_Table :: #import "Hash_Table";
#import "File";
#import "IO";
#import "LibAV";
#import "Log";
#import "Net";
#import "OpenSSL";
#import "POSIX";
#import "Socket";
#import "String";
#import "ICE";
#import "PeerConnection";
#import "Rtp";
#import "Sdp";
#import "Stun";
#import "jaison";

IO_Read_Kind :: struct {
  type: Type;
};

IO_TCP_Read :: struct {
  #as using kind: IO_Read_Kind;
};

IO_UDP_Read :: struct (T: Type){
  #as using kind: IO_Read_Kind;
  sock_conn: Socket_Connection;
  pc: *Peer_Connection(T);
  buf: []u8;
  msg_hdr: *msghdr;
};

IO_File_Read :: struct {
  #as using kind: IO_Read_Kind;
  from: File;
  buf: []u8;
};

open_stream :: () {
  fmt_ctx := avformat_alloc_context();
  assert(fmt_ctx != null);
  filename := temp_c_string("./resources/video.h264");
  ret := avformat_open_input(*fmt_ctx, filename, null, null);
  assert(ret == 0);

  ret = avformat_find_stream_info(fmt_ctx, null);
  assert(ret == 0);

  src_video_stream: *AVStream = null;

  for 0 .. fmt_ctx.nb_streams-1 {
    stream := fmt_ctx.streams[it];
    if stream.codecpar.codec_type == AVMediaType.VIDEO src_video_stream = stream;
  }

  assert(src_video_stream != null);

  log("Stream #%: codec_type=%\n", src_video_stream.index,
            src_video_stream.codecpar.codec_id);

  read_pkt := av_packet_alloc();

  rtp_sender := rtp_sender_new("127.0.0.1", 5000);
  iter := 0;

  while av_read_frame(fmt_ctx, read_pkt) >= 0 {
    FPS :: 1/25.;

    start_time := current_time_monotonic();

    if read_pkt.stream_index == src_video_stream.index {
      as_slice: []u8 = ---;
      as_slice.data = read_pkt.data;
      as_slice.count = read_pkt.size;

      while true {
        nalu, rest, ok := extract_nalu(as_slice);
        if !ok break;
        if nalu[0]&0x1f >= 23 || nalu[0]&0x1f == 0 {
          print("nalu is %\n", nalu); assert(false);
        }
        timestamp := av_rescale_q(iter, .{1, 90000}, .{1, 25});
        iter += 1;
        write_rtp(*rtp_sender, nalu, xx timestamp);
        as_slice = rest;
      }

      end_time := current_time_monotonic();
      delta := to_milliseconds(end_time - start_time);

      sleep_milliseconds(xx (FPS * 1000  - delta));

    } else assert(false, "cowabunga");

  }
}
handle_stun_bind_request :: (pc: *Peer_Connection, from: Socket_Address, msg: Stun_Message) {
  // @todo itegrity and all the other checks here
  reply := stun_message_prepare(
    .BIND |.SUCCESS_RESPONSE,
    stun_attribute_xor_mapped(from),
    stun_attribute_integrity(UPWD),
  );
  // stun_message_send(we, from, reply);
}

handle_stun_success_response :: (pc: *Peer_Connection, msg: Stun_Message, from: Socket_Address) {
  // @note there should be some timeout somewhere that invalidates checking for a pair
  // if we get a bind response we should reset the timeout or something like that idk
  // msg := stun_message_prepare(.BIND,
  //   stun_attribute_username(UFRAG, candidate.ufrag),
  //   stun_attribute_ice_controlled(0xbaface7fad843c7b),
  //   stun_attribute_priority(0x7effffff),
  //   stun_attribute_integrity(pwd),
  //   stun_attribute_fingerprint(),
  // );
  // candidate_sock: SocketAddress = .{
  //   ip_addr_from_string(candidate.connection_addr),
  //   candidate.port,
  // };
  //
  // print("sent to %:%\n",to_string(candidate_sock.addr), candidate.port);
  //
  // sz = stun_message_send(host.socket, candidate_sock, *msg_another_one);
}
on_udp_packet :: (pc: *Peer_Connection, from: Socket_Address, packet: []u8) {
  msg := stun_message_serialize(packet);
  sane := stun_header_kind_sane(msg);
  assert(msg.kind & xx Stun_Message_Kind.BIND != 0, tprint("unknown kind %", msg.kind));
  // if sane == {
  //   case .REQUEST; handle_stun_bind_request(pc.socket_connection, from, packet);
  //   case .SUCCESS_RESPONSE; handle_stun_bind_request();
  //   case .ERROR_RESPONSE; assert(false, "ERROR_RESPONSE is not implemented!");
  //   case .INDICATION; assert(false, "INDICATION is not implemented!");
  // }
}

create_msghdr :: (buf: []u8) -> *msghdr {
  iov := New(iovec,, allocator = temp);
  iov.* = .{
    iov_base = xx buf.data,
    iov_len = xx buf.count,
  };
  addr := New(sockaddr_storage,, allocator = temp);

  msg := New(msghdr,, allocator = temp);
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  msg.msg_name = xx addr;
  msg.msg_namelen = size_of(sockaddr_in);
  return msg;

}

on_io_udp_read :: (pc: *Peer_Connection(*IO_Uring), read_ctx: *IO_UDP_Read(*IO_Uring), from: Socket_Address, buf: []u8) {
  msg := stun_message_serialize(buf);

  sb: String_Builder;

  // from is a peer reflexive address
  response := stun_message_prepare_binding_response(from, get_local_ice_pwd(pc), msg.transaction_id);

  assert(read_ctx.sock_conn.sock > 2);
  stun_message_send(*response, read_ctx.sock_conn.sock, from);

  as_uring := cast(*IO_Uring)read_ctx.pc.udata;

  sqe := uring_op_recvmsg(as_uring, read_ctx.sock_conn.sock, read_ctx.msg_hdr, 0, read_ctx);
  assert(sqe != null);
}

get :: (json_val: JSON_Value, key: string, expected_type: JSON_Type) -> JSON_Value, bool {
  assert(json_val.type == .OBJECT);
  table := json_val.object;
  val, success := Hash_Table.table_find(table, key);
  if !success return val, false;
  assert(val.type == expected_type);
  return val, success;
}

on_ice_candidate_cb :: (pc: *Peer_Connection(*IO_Uring), candidate: *Ice_Candidate, udata: **IO_Uring) {
  sb: String_Builder = .{ allocator = temporary_allocator };
  as_str := to_chrome_ice_candidate_shit(*sb, candidate);
  print("%\n",as_str);
  buf := cast([]u8) alloc_string(MTU);
  hdr := create_msghdr(buf);
  on_io_udata := New(IO_UDP_Read(*IO_Uring),, allocator = temp);
  // @refactor move this to temp storage of that is persistent for the
  // life time of this request??
  on_io_udata.* = .{
    pc = pc,
    buf = buf,
    type = IO_UDP_Read(*IO_Uring),
    msg_hdr = hdr,
    sock_conn = candidate.socket_connection,
  };
  sqe := uring_op_recvmsg(udata.*, candidate.socket_connection.sock, hdr, 0, xx on_io_udata);
  assert(sqe != null);
}


main :: () {
  params: IO_Uring_Params;
  uring := New(IO_Uring);
  err := uring_init(uring, *params);
  if err != .Success { log_err("got error and shit bru %\n", err); assert(false); }

  peer_config := Peer_Configuration.{
    ice_config = .{ stun_servers = .[.{ "stun.l.google.com", 19302 }] },
  };

  pc := new_peer_connection(peer_config, uring);
  on_ice_candidate(*pc, on_ice_candidate_cb);

  local_desc, parse_err := parse_sdp(ANSWER_DC_ONLY);
  assert(parse_err == .Success, "we are cooked bru");
  set_local_description(*pc, local_desc);

  // this should be internal to peerconnection after we have set the local description
  gather_local_candidates(*pc);

  // @leak
  file_read_op := New(IO_File_Read);
  file_read_op.* = .{
    type = IO_File_Read,
    from = .{},
    buf = xx alloc_string(4096 + 2048),
  };
  sqe := uring_op_read(uring, STDIN_FILENO, file_read_op.buf, xx file_read_op); assert(sqe != null);

  cqes_original: [5] IO_Uring_CQE;
  cqes := array_view(cqes_original, 0, 5);
  while true {
    n_submitted, os_err := uring_submit(uring);
    if n_submitted <= 0 && cq_ready(uring) <= 0 continue;
    copied:, os_err = cqes_copy(uring, cqes, 1);
    if os_err {
      log_err("error occured while cqes_copy : %\n", os_err);
      assert(false);
    }

    for copied {
      // here we should remove the event from the peer connection or something like that
      udata := it.user_data;
      kind := cast(*IO_Read_Kind)udata;
      if kind.type == {
        case IO_TCP_Read();
          assert(false, "unimplemented!");

        // we can't cast from a runtime type
        case IO_UDP_Read(*IO_Uring);
          if it.res <= 0 {
            print("error occured while reading from the socket %\n",to_string(hstrerror(errno())));
            continue;
          };
          udp_read := cast(*IO_UDP_Read(*IO_Uring)) kind;
          sin := cast(*sockaddr_in)udp_read.msg_hdr.msg_name;
          buf := array_view(udp_read.buf, 0, it.res);
          sock_addr := socket_address_from_sockaddr(sin);
          on_io_udp_read(*pc, udp_read, sock_addr, buf);
        case IO_File_Read; // @TODO @priority this assumes that this will always be a line
          if it.res < 0 {
            print("File Closed!\n"); assert(false);
            continue;
          }
          file_read := cast(*IO_File_Read) kind;
          line: string = xx array_view(file_read.buf, 0, it.res);
          ok, root := json_parse_string(line);
          assert(ok, tprint("not a valid json '%'\n", line));
          sdp:, ok = get(root, "sdp", .STRING);
          if ok {
            typ:, ok = get(root, "type", .STRING);
            assert(ok);
            assert(equal(typ.str, "offer"));
            parsed_sdp := parse_sdp(sdp.str);
            set_remote_description(*pc, parsed_sdp);
          }else {
            candidate, ok := get(root, "candidate", .STRING);
            if ok { print("got candidate bro less goo\n"); }
          }
          sqe := uring_op_read(uring, STDIN_FILENO, file_read.buf, xx file_read_op);
          assert(sqe != null);
      };
    }
  }
  // builder: String_Builder;
  // sz: s64;
  //
  // // only for single candidate
  // io_add_event(io, xx host.socket, .READ, xx *host_candidates[0]);
  //
  // while true {
  //   events:= io_tick();
  //   for events {
  //
  //   if it.events & xx Event_Kind.IN  != 0 {
  //     buffer: [MTU]u8;
  //     while true {
  //       bytes, err, addr := udp_recv_from();
  //       if (err & (EWOULDBLOCK | EAGAIN)) != 0 break;
  //       if bytes.count == 0 {
  //         // we read zero bytes meaning the connection is closed do smth here
  //         assert(false);
  //       }
  //       on_udp_packet(xx it.data.ptr, addr, bytes);
  //     }
  //   }
  //   if it.events & xx Event_Kind.OUT != 0 {
  //     assert(false, "unreachable"); // for now
  //   }
  //   if it.events & EPOLLERR != 0 {
  //     error: s32 = 0;
  //     errlen: s32 = size_of(s32);
  //     assert(it.data.fd > 2);
  //     ret := getsockopt(it.data.fd, SOL_SOCKET, SO_ERROR, xx *error, *errlen); assert(ret == 0);
  //     // add better logging
  //     log_error("error occured on socket fd %: %s\n", to_string(hstrerror(error)));
  //   }
  //   if it.events & EPOLLRDHUP  != 0 { log_info("socket fd % is closed\n"); }
  //   }
  // }



  // first shit
  // sz, sock_info = udp_recv_from(xx host.socket, *cast([]u8)slice);
  // first_msg := stun_message_serialize(array_view(cast([]u8) slice, 0, sz));
  //
  // ok:, usrname_attr := stun_message_try_get_attribute(first_msg, Stun_Attribute_Username);
  //
  // print("sock_info.port %\n",sock_info.port);
  // reply := stun_message_prepare(.BIND |.SUCCESS_RESPONSE,
  //   // fix this
  //   stun_attribute_xor_mapped(sock_info),
  //   stun_attribute_integrity(UPWD),
  // );
  // reply.header.transaction_id = first_msg.header.transaction_id;
  // sz = stun_message_send(host.socket, sock_info, *reply);

  // pwd := readline();
  // line := readline();
  //
  // candidate := parse_ice_candidate_string(line);
  // assert(candidate.ufrag.count != 0);
  //
  // msg_another_one := stun_message_prepare(.BIND,
  //   stun_attribute_username(UFRAG, candidate.ufrag),
  //   stun_attribute_ice_controlled(0xbaface7fad843c7b),
  //   stun_attribute_priority(0x7effffff),
  //   stun_attribute_integrity(pwd),
  //   stun_attribute_fingerprint(),
  // );
  // candidate_sock: SocketAddress = .{
  //   ip_addr_from_string(candidate.connection_addr),
  //   candidate.port,
  // };
  //
  // print("sent to %:%\n",to_string(candidate_sock.addr), candidate.port);
  //
  // sz = stun_message_send(host.socket, candidate_sock, *msg_another_one);
  // assert(sz != -1);
  // print("sent the message and shit or smth\n");
  //
  // sz, sock_info = udp_recv_from(xx host.socket, *cast([]u8)slice);
  // msg := stun_message_serialize(array_view(cast([]u8) slice, 0, sz));
  // msg_as_str := to_string(*builder, msg);
  // print("got reply to our request now i guess\n");
  // print(msg_as_str);
  // while true {};
}

// i can't belive i have to write this
readline :: () -> string {
  buffer := alloc_string(1024);
  bytes_read := read(STDIN_FILENO, buffer.data, cast(u64) buffer.count);
  if bytes_read > 0 buffer.count = bytes_read;
  return trim(buffer);
}
