#import "Basic";
#import "SRTP";
#import "utils";
#import "Compiler";
#import "DTLS";
#import "File";
#import "ICE";
#import "IO";
#import "LibAV";
#import "Log";
#import "Net";
#import "OpenSSL";
#import "POSIX";
#import "PeerConnection";
#import "Rtp";
#import "Sdp";
#import "Socket";
#import "Tagged_Union";
#import "String";
#import "Stun";
#import "jaison";
Hash_Table :: #import "Hash_Table";

IO_OP_Kind :: struct {
  type: Type;
};

IO_TCP_Read :: struct {
  #as using kind: IO_OP_Kind;
};

IO_UDP_Read :: struct (T: Type){
  #as using kind: IO_OP_Kind;
  sock_conn: Socket_Connection;
  pc: *Peer_Connection(T);
  buf: []u8;
  msg_hdr: *msghdr;
};

IO_File_Read :: struct {
  #as using kind: IO_OP_Kind;
  from: File;
  buf: []u8;
};

IO_Timeout :: struct(T: Type) {
  #as using kind: IO_OP_Kind;
  pc: *Peer_Connection(T);
  timeout: *Time_Spec; // actual timeout that we did
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
  msg := stun_message_deserialize(packet);
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
  iov := New(iovec);
  iov.* = .{
    iov_base = xx buf.data,
    iov_len = xx buf.count,
  };
  addr := New(sockaddr_storage);

  msg := New(msghdr);
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  msg.msg_name = xx addr;
  msg.msg_namelen = size_of(sockaddr_in);
  return msg;

}

do_connectivity_check_for_pair :: (pc: *Peer_Connection(*IO_Uring)) {

  for * pc.check_list.pairs {
    // @todo this should be media level not session level
    pwd := pc.remote_description.sls.ice_pwd;

    // @todo @proirity the tie breaker is hardcoded and we do not compute priority
    msg := stun_message_prepare(.BIND,
      stun_attribute_username(it.local.ufrag, it.remote.ufrag),
      stun_attribute_ice_controlled(0xbaface7fad843c7b),
      stun_attribute_priority(0x7effffff),
      stun_attribute_integrity(pwd),
      stun_attribute_fingerprint(),
    );

    candidate_sock: Socket_Address = .{
      ip_addr_from_string(it.remote.connection_addr),
      htons(it.remote.port),
    };

    // log_debug("connectivity check %:% -> %:%\n",
    //   to_string(it.local.socket_connection.addr), it.local.socket_connection.port,
    //   to_string(candidate_sock.addr), ntohs(candidate_sock.port)
    // );

    assert(it.local.socket_connection.sock > 2);
    sz := stun_message_send(*msg, it.local.socket_connection.sock, candidate_sock);
    assert(sz != -1);
  }
}

on_io_udp_read :: (pc: *Peer_Connection(*IO_Uring), read_ctx: *IO_UDP_Read(*IO_Uring), from: Socket_Address, buf: []u8) {
  // https://datatracker.ietf.org/doc/html/rfc5764#section-5.1.2
  if 127 < buf[0] && buf[0] < 192 { // rtp
  }else if 19 < buf[0] && buf[0] < 64 { // dtls
    dtls_ctx := *pc.dtls_ctx;
    print("got dtls packet less gooo!\n");
    msg := dtls_message_deserialize(buf);
    ok := dtls_message_get_cookie(msg);
    if !ok {
      verify := dtls_message_hello_verify(dtls_ctx, msg, dtls_generate_cookie());
      serialized := dtls_message_serialize(*verify);
      sz := udp_write(read_ctx.sock_conn.sock, from, xx serialized);
      assert(sz == serialized.count , tprint("udp write returned %: %\n", sz, strerror(errno())));
      return;
    }
    if msg.header.kind == .CLIENT_HELLO {
      srtp_ext := srtp_get_extensions(.AES128_CM_HMAC_SHA1_80, mki = .[]);
      reply := dtls_message_server_hello(dtls_ctx, msg, .[srtp_ext]);
      serialized := dtls_message_serialize(*reply);
      sz := udp_write(read_ctx.sock_conn.sock, from, xx serialized);
      assert(sz == serialized.count , tprint("udp write returned %: %\n", sz, strerror(errno())));

      reply = dtls_message_server_hello_done(dtls_ctx);
      serialized = dtls_message_serialize(*reply);
      sz = udp_write(read_ctx.sock_conn.sock, from, xx serialized);
      assert(sz == serialized.count , tprint("udp write returned %: %\n", sz, strerror(errno())));

    }
  }else if buf[0] < 2 { // stun
    dtls_ctx := *pc.dtls_ctx;
    msg := stun_message_deserialize(buf);
    as_sane := stun_header_kind_sane(msg);
    if as_sane == {
      case .REQUEST; {
        // from is a peer reflexive address
        response := stun_message_prepare_binding_response(from, get_local_ice_pwd(pc), msg.transaction_id);

        assert(read_ctx.sock_conn.sock > 2);
        stun_message_send(*response, read_ctx.sock_conn.sock, from);
      }
      case .INDICATION; assert(false, "INDICATION unimplemented!");
      case .SUCCESS_RESPONSE; {
        val, ok := Hash_Table.table_find(*pc.check_list.tid_lut, msg.transaction_id);
        if !ok {
          id := msg.transaction_id;
          log_err("failed to get ice pair for t_id %_%\n", id.first, id.second);
          assert(false);
        }
        val.is_connected = true;

        // dtls_hello := dtls_client_hello();
        // serialized := dtls_message_serialize();
        // sz := udp_write(read_ctx.sock_conn.sock, from, xx serialized);
        // assert(sz == serialized.count , tprint("udp write returned %: %\n", sz, strerror(errno())));
        // @todo we need to handle this to implement failing of ice connection
      }
      case .ERROR_RESPONSE; assert(false, "unimplemented!");
    }
  } else {
    assert(false, "unreachable");
  }
}

get :: (json_val: JSON_Value, key: string, expected_type: JSON_Type) -> JSON_Value, bool {
  assert(json_val.type == .OBJECT);
  table := json_val.object;
  val, success := Hash_Table.table_find(table, key);
  if !success return val, false;
  assert(val.type == expected_type);
  return val, success;
}

new_io_stdin_read_event :: (uring: *IO_Uring) -> *IO_Uring_SQE {
  // @perf
  file_read_op := New(IO_File_Read);
  file_read_op.* = .{
    type = IO_File_Read,
    from = .{},
    buf = xx alloc_string(4096 + 2048),
  };
  sqe := uring_op_read(uring, STDIN_FILENO, file_read_op.buf, xx file_read_op); assert(sqe != null);
  assert(sqe != null);
  return sqe;
}

new_io_timeout_event :: (uring: *IO_Uring, timeout: Time_Spec, pc: *Peer_Connection($T)) -> *IO_Uring_SQE {
  // @perf not really but do not do malloc here
  timespec := New(Time_Spec);
  timespec.* = timeout;

  io_timeout_op := New(IO_Timeout(type_of(pc.udata)));
  io_timeout_op.* = .{
    type = IO_Timeout(type_of(pc.udata)),
    pc = pc,
    timeout = timespec,
  };

  sqe := uring_op_timeout(uring, timespec, io_timeout_op);
  assert(sqe != null);
  return sqe;
}

on_ice_candidate_cb :: (pc: *Peer_Connection(*IO_Uring), candidate: *Ice_Candidate, udata: **IO_Uring) {
  sb: String_Builder;
  as_str := to_chrome_ice_candidate_shit(*sb, candidate,, allocator = temp);
  print("%\n",as_str);

  buf := cast([]u8) alloc_string(MTU);
  hdr := create_msghdr(buf);
  on_io_udata := New(IO_UDP_Read(*IO_Uring));
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
set_pp :: () {
  context.print_style.default_format_struct.draw_type_name = true;
  context.print_style.default_format_struct.use_long_form_if_more_than_this_many_members = -1;
  context.print_style.default_format_struct.use_newlines_if_long_form = true;
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

  new_io_stdin_read_event(uring);
  new_io_timeout_event(uring, Time_Spec.{1,0}, *pc);


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
      udata := it.user_data;
      kind := cast(*IO_OP_Kind)udata;
      if kind.type == {
        case IO_TCP_Read();
          assert(false, "unimplemented!");

        // we can't cast from a runtime type
        case IO_UDP_Read(*IO_Uring);
          if it.res <= 0 {
            print("error occured while reading from the socket %\n",strerror(errno()));
            continue;
          };
          udp_read := cast(*IO_UDP_Read(*IO_Uring)) kind;
          sin := cast(*sockaddr_in)udp_read.msg_hdr.msg_name;
          buf := array_view(udp_read.buf, 0, it.res);
          sock_addr := socket_address_from_sockaddr(sin);
          on_io_udp_read(*pc, udp_read, sock_addr, buf);

          as_uring := cast(*IO_Uring)udp_read.pc.udata;
          sqe := uring_op_recvmsg(as_uring, udp_read.sock_conn.sock, udp_read.msg_hdr, 0, udp_read);
          assert(sqe != null);
        case IO_File_Read; // @TODO @priority this assumes that this will always be a line
          // @todo @priority this is ass as we just use scope variables like pc and all without
          // taking it from IO_File_Read
          if it.res < 0 {
            log_err("File Closed!\n"); assert(false);
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
            candidate_jvalue, ok := get(root, "candidate", .STRING);
            if !ok continue;
            // @leak
            candidate_str := copy_string(candidate_jvalue.str);
            candidate := parse_ice_candidate_string(candidate_str);
            add_ice_candidate(*pc, candidate);
            // figure out all the bs with the component id shit bru
            assert(pc.check_list.pairs.count != 0);
          }
          sqe := uring_op_read(uring, STDIN_FILENO, file_read.buf, xx file_read);
          assert(sqe != null);

        case IO_Timeout(*IO_Uring);
          assert(it.res == 0 || it.res == -62); // handle cancel time out or smth like that??? idk

          as_timeout := cast(*IO_Timeout(*IO_Uring)) kind;
          do_connectivity_check_for_pair(as_timeout.pc);

          // we can have a multishoot timeout but nah cause kernel>6.4 and we will have to do cancellations
          sqe := uring_op_timeout(as_timeout.pc.udata, as_timeout.timeout, as_timeout);
          assert(sqe != null);
      };
      reset_temporary_storage();
    }
  }
}
