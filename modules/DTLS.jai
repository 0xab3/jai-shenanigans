DTLS_VERSION_1_2 :: DTLS_Protocol_Version.{0xfe, 0xfd}; // dtls version 1.2

TLS_RSA_WITH_AES_128_CBC_SHA :: DTLS_Cipher_Suite.{0x00, 0x2f};
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 :: DTLS_Cipher_Suite.{0xC0, 0x2f};

DTLS_SUPPORTED_CIPHER_SUITES :: DTLS_Cipher_Suite.[
  TLS_RSA_WITH_AES_128_CBC_SHA,
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];

DTLS_Context :: struct {
  seq_no: Pair(u32, u16);
};


operator + :: (x: Pair(u32, u16), y: s64) -> Pair(u32, u16) {
  as_s64 := cast(s64) x.second;
  // i don't have time to do this
  if as_s64 + y > 0xffff assert(false, "unimplemented!");
  p := Pair(u32, u16).{
    first = x.first,
    second = x.second + xx y,
  };
  return p;
}

DTLS_Protocol_Version :: struct {
  _: void; @Size @2
  major: u8; @Size @1
  minor: u8; @Size @1
};

DTLS_Content_Kind :: enum u8 {
  CHANGE_CIPHER_SPEC  ::  20;
  ALERT               ::  21;
  HANDSHAKE           ::  22;
  APPLICATION_DATA    ::  23;
};

DTLS_Handshake_Kind :: enum u8 {
  HELLO_REQUEST         ::   00;
  CLIENT_HELLO          ::   01;
  SERVER_HELLO          ::   02;
  HELLO_VERIFY_REQUEST  ::   03;
  CERTIFICATE           ::   11;
  SERVER_KEY_EXCHANGE   ::   12;
  CERTIFICATE_REQUEST   ::   13;
  SERVER_HELLO_DONE     ::   14;
  CERTIFICATE_VERIFY    ::   15;
  CLIENT_KEY_EXCHANGE   ::   16;
  FINISHED              ::   20;
};


_get_gm_time :: () -> u32 {
  return xx time(null);
}

DTLS_Random :: struct {
  _: void; @Size @32
  gmt_unix_time: u32; @Size @4
  random_bytes: [28]u8; @Array @28
};

DTLS_Compression_Method :: enum u8 {
  NULL :: 0;
};
DTLS_Cipher_Suite :: struct {
  _: void; @Size @2
  lower: u8; @Size @1
  upper: u8; @Size @1
};

operator == :: (x: DTLS_Cipher_Suite, y: DTLS_Cipher_Suite) -> bool {
  return x.lower == y.lower && x.upper == y.upper;
}

// this is the plain text thingy but idk we need anything more than this as we only
// use dtls for key exchange
DTLS_Record :: struct {
  kind: DTLS_Content_Kind; @DefaultSize
  version: DTLS_Protocol_Version; @InnerSize
  epoch: u16; @Size @2
  seq_no: Pair(u32, u16); @DefaultSize
  length: u16; @Size @2 // length of the Handshake header + value
};

DTLS_RECORD_SIZE :: #run dtls_message_get_size(DTLS_Record);

DTLS_Handshake_Header :: struct {
  kind: DTLS_Handshake_Kind; @DefaultSize
  length: u32; @Array @3
  message_seq: u16; @DefaultSize
  fragment_offset: u32; @Array @3
  fragment_length: u32; @Array @3
};
DTLS_HANDSHAKE_HEADER_SIZE :: #run dtls_message_get_size(DTLS_Handshake_Header);

DTLS_Client_Hello :: struct {
  client_version: DTLS_Protocol_Version;
  random: DTLS_Random;
  session_id: []u8;  @Vla @1
  cookie: []u8; @Vla @1
  cipher_suites: []DTLS_Cipher_Suite; @Vla @2
  compression_methods: []DTLS_Compression_Method;  @Vla @1
  extensions: []DTLS_Extension; @Vla @2
};

DTLS_Extension :: struct {
  kind: DTLS_Extension_Kind; @Size @2
  data: []u8; @Vla @2
};

DTLS_Extension_Kind :: enum u16 {
  SIGNATURE_ALGORITHMS :: 13;
  SRTP_EXTENSION       :: 14; // i sacrifice the api boundary for better errors
  EXTEND_MASTER_SECRET :: 23;
};

DTLS_Server_Hello :: struct {
  server_version: DTLS_Protocol_Version = .{0xfe, 0xff}; @InnerSize // 1.0 
  random: DTLS_Random; @InnerSize
  session_id: []u8; @Vla @1
  cipher_suite: DTLS_Cipher_Suite; @DefaultSize
  compression_method: DTLS_Compression_Method; @Size @1
  extensions: []DTLS_Extension; @Vla @2
};

_extensions_size_in_bytes :: (exts: []DTLS_Extension) -> s64 #expand {
  total_length := 2 + exts.count * 2;
  for exts {
    total_length += it.data.count;
  }
  return total_length;
}

// @note the rfc talks about sm 1.0 but i don't understand it and 1.2 works so
// we don't care right now
// https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.1
DTLS_Hello_Verify :: struct {
  server_version: DTLS_Protocol_Version = DTLS_Protocol_Version.{0xfe, 0xff}; @InnerSize
  cookie: []u8;  @Vla @1
};

DTLS_Server_Hello_Done :: struct {};

DTLS_Handshake_Value :: Tagged_Union(
  DTLS_Client_Hello,
  DTLS_Hello_Verify,
  DTLS_Server_Hello,
  DTLS_Server_Hello_Done,
);

DTLS_Handshake_Message :: struct {
  record: DTLS_Record;
  header: DTLS_Handshake_Header;
  value: DTLS_Handshake_Value;
};

to_string :: (record: *DTLS_Record, tab := "") -> string {
  sb := String_Builder.{
    allocator = temporary_allocator,
  };
  r := record;
  seq_hi := r.seq_no.first;
  seq_lo := r.seq_no.second;
  print_to_builder(*sb, "%DTLS_Record {\n", tab);
  print_to_builder(*sb, "%  kind: %\n", tab, r.kind);
  print_to_builder(*sb, "%  version: %.%\n", tab, ~r.version.major, ~r.version.minor);
  print_to_builder(*sb, "%  epoch: %\n", tab, r.epoch);
  print_to_builder(*sb, "%  seq_no: (%, %)\n", tab, seq_hi, seq_lo);
  print_to_builder(*sb, "%  length: %\n", tab, r.length);
  print_to_builder(*sb, "%}\n", tab);
  return builder_to_string(*sb);
}

to_string :: (hdr: *DTLS_Handshake_Header, tab := "") -> string {
  sb := String_Builder.{ allocator = temporary_allocator };
  print_to_builder(*sb, "%DTLS_Handshake_Header {\n", tab);
  print_to_builder(*sb, "%  kind: %\n", tab, hdr.kind);
  print_to_builder(*sb, "%  length: %\n", tab, hdr.length);
  print_to_builder(*sb, "%  message_seq: %\n", tab, hdr.message_seq);
  print_to_builder(*sb, "%  fragment_offset: %\n", tab, hdr.fragment_offset);
  print_to_builder(*sb, "%  fragment_length: %\n", tab, hdr.fragment_length);
  print_to_builder(*sb, "%}\n", tab);
  return builder_to_string(*sb);
}

to_string :: (value: DTLS_Handshake_Value, tab := "") -> string {
  as_hello := isa(value, DTLS_Client_Hello);
  if as_hello != null return to_string(as_hello, tab);

  as_hello_verify := isa(value, DTLS_Hello_Verify);
  if as_hello_verify != null return to_string(as_hello_verify, tab);
  assert(false, tprint("type % is not implemented", value.tag));
  return "";
}

to_string :: (value: *DTLS_Hello_Verify, tab := "") -> string {
  sb := String_Builder.{ allocator = temporary_allocator };
  server_version := value.server_version;
  print_to_builder(*sb, "%DTLS_Hello_Verify {\n", tab);
  print_to_builder(*sb, "%  server_version: %.%\n", tab, ~server_version.major, ~server_version.minor);
  print_to_builder(*sb, "%  cookie: %\n", tab, hex_string(value.cookie));
  print_to_builder(*sb, "%}\n", tab);
  return builder_to_string(*sb);
}

to_string :: (ch: *DTLS_Client_Hello, tab := "") -> string {
  sb := String_Builder.{ allocator = temporary_allocator };
  random_bytes_as_hex_string := hex_string(ch.random.random_bytes,, allocator = temp);
  print_to_builder(*sb, "%DTLS_Client_Hello {\n", tab);
  print_to_builder(*sb, "%  client_version: %.%\n", tab, ~ch.client_version.major, ~ch.client_version.minor);
  print_to_builder(*sb, "%  random: %_%\n", tab, formatHex(ch.random.gmt_unix_time), random_bytes_as_hex_string);
  print_to_builder(*sb, "%  session_id: [", tab);
  for 0..ch.session_id.count-1 {
    print_to_builder(*sb, "%", ch.session_id[it]);
    if it < ch.session_id.count - 1 print_to_builder(*sb, ", ");
  }
  print_to_builder(*sb, "]\n");

  print_to_builder(*sb, "%  cookie: [", tab);
  for 0..ch.cookie.count-1 {
    print_to_builder(*sb, "%", ch.cookie[it]);
    if it < ch.cookie.count - 1 print_to_builder(*sb, ", ");
  }
  print_to_builder(*sb, "]\n");

  suites := ch.cipher_suites;
  print_to_builder(*sb, "%  cipher_suites: [\n", tab);
  for 0..suites.count-1 print_to_builder(*sb, "%    [%,%]\n", tab, formatHex(suites[it][0]), formatHex(suites[it][1]));
  print_to_builder(*sb, "%  ]\n", tab);

  print_to_builder(*sb, "%  compression_methods: [\n", tab);
  for 0..ch.compression_methods.count-1 print_to_builder(*sb, "%    %\n", tab, ch.compression_methods[it]);
  print_to_builder(*sb, "%  ]\n", tab);
  print_to_builder(*sb, "%}\n", tab);
  return builder_to_string(*sb);
}

to_string :: (msg: *DTLS_Handshake_Message) -> string {
  sb := String_Builder.{ allocator = temporary_allocator };
  rcd := to_string(*msg.record, "    ");
  hdr := to_string(*msg.header, "    ");
  handshake := to_string(*msg.value, "    ");
  print_to_builder(*sb, "DTLS_Message {\n");
  print_to_builder(*sb, "%", rcd);
  print_to_builder(*sb, "%", hdr);
  print_to_builder(*sb, "%", handshake);
  print_to_builder(*sb, "}\n");
  return builder_to_string(*sb);
}

_dtls_record_deserialize :: (reader: *Bytes_Reader) -> DTLS_Record {
  kind := read_bytes(reader, u8);

  version_hi := read_bytes(reader, u8);
  version_lo := read_bytes(reader, u8);

  epoch := read_bytes(reader, u16);
  seq_no: Pair(u32, u16);
  seq_no.first = read_bytes(reader, u32);
  seq_no.second = read_bytes(reader, u16);

  version := DTLS_Protocol_Version.{
    major = version_hi,
    minor = version_lo,
  };

  length := read_bytes(reader, u16);
  return .{
    kind = xx kind,
    version = version,
    epoch = epoch,
    seq_no = seq_no,
    length = length,
  };
}

_dtls_handshake_header_deserialize :: (reader: *Bytes_Reader) -> DTLS_Handshake_Header {
  msg_kind := read_bytes(reader, u8);
  msg_length := read_string(reader, 3);
  msg_seq := read_bytes(reader, u16);
  msg_frag_offset := read_string(reader, 3);
  msg_len_offset := read_string(reader, 3);

  return .{
    kind = xx msg_kind,
    length = bytes_to_int(msg_length, u32),
    message_seq = xx msg_seq,
    fragment_offset = bytes_to_int(msg_frag_offset, u32),
    fragment_length = bytes_to_int(msg_len_offset, u32),
  };
}

_dtls_client_hello_deserialize :: (reader: *Bytes_Reader) -> DTLS_Client_Hello {
  version_hi := read_bytes(reader, u8);
  version_lo := read_bytes(reader, u8);

  version := DTLS_Protocol_Version.{
    major = version_hi,
    minor = version_lo,
  };

  gmt_unix_time := read_bytes(reader, u32);
  random_bytes := read_string(reader, 28);

  rnd := DTLS_Random.{
    gmt_unix_time = gmt_unix_time,
    random_bytes = random_bytes,
  };

  session_id: []u8;
  session_id_length := read_bytes(reader, u8);
  if session_id_length > 0 {
    // @leak this should be on temporary allocator in peer context or something bru
    session_id = xx copy_string(xx read_string_no_copy(reader, session_id_length));
  }
  cookie: []u8;
  cookie_length := read_bytes(reader, u8);
  if cookie_length > 0 {
    // @leak this should be on temporary allocator in peer context or something bru
    cookie = xx copy_string(xx read_string_no_copy(reader, cookie_length));
  }
  cipher_suite_length := read_bytes(reader, u16) / 2;
  cipher_suites: [..]DTLS_Cipher_Suite;

  // @leak this should be on temporary allocator in peer context or something bru
  array_reserve(*cipher_suites, cipher_suite_length);
  for 0..cipher_suite_length-1 {
    cipher_hi := read_bytes(reader, u8);
    cipher_lo := read_bytes(reader, u8);
    array_add(*cipher_suites, .{cipher_hi, cipher_lo});
  }

  compression_method: []DTLS_Compression_Method;
  compression_method_length := read_bytes(reader, u8);
  if compression_method_length > 0 {
    // @leak this should be on temporary allocator in peer context or something bru
    compression_method = cast,force([]DTLS_Compression_Method) (cast([]u8) copy_string(xx read_string_no_copy(reader, compression_method_length)));
  }

  return .{
    client_version = version,
    random = rnd,
    session_id = session_id,
    cookie = cookie,
    cipher_suites = cipher_suites,
    compression_methods = compression_method,
  };
}
_dtls_hello_verify_request_deserialize :: (reader: *Bytes_Reader) -> DTLS_Hello_Verify {
  version_hi := read_bytes(reader, u8);
  version_lo := read_bytes(reader, u8);

  version := DTLS_Protocol_Version.{
    major = version_hi,
    minor = version_lo,
  };

  cookie: []u8;
  cookie_length := read_bytes(reader, u8);
  print("cookie length read is this %\n", cookie_length);
  if cookie_length > 0 {
    // @leak this should be on temporary allocator in peer context or something bru
    cookie = xx copy_string(xx read_string_no_copy(reader, cookie_length));
  }
  return .{
    server_version = version,
    cookie = cookie,
  };
}

_dtls_handshake_deserialize :: (reader: *Bytes_Reader, kind: DTLS_Handshake_Kind) -> DTLS_Handshake_Value {
  as_value: DTLS_Handshake_Value;
  if kind == {
    case .CLIENT_HELLO; {
      value := _dtls_client_hello_deserialize(reader);
      set(*as_value, value);
    }
    case .HELLO_VERIFY_REQUEST; {
      value := _dtls_hello_verify_request_deserialize(reader);
      set(*as_value, value);
    }
    case;{
    assert(kind == .CLIENT_HELLO, tprint("dtls handshake kind % is not implemented!", kind));
    }
  }
  return as_value;
}


dtls_message_deserialize :: (buf: []u8) -> DTLS_Handshake_Message {
  reader := Bytes_Reader.{ bytes = buf };
  rcd := _dtls_record_deserialize(*reader);
  msg_hdr := _dtls_handshake_header_deserialize(*reader);
  handshake := _dtls_handshake_deserialize(*reader, msg_hdr.kind);

  msg := DTLS_Handshake_Message.{
    header = msg_hdr,
    record = rcd,
    value = handshake,
  };
  return msg;
}

dtls_handsake_record_default :: (seq_no: Pair(u32,u16)) -> DTLS_Record {
  return .{
    kind = .HANDSHAKE,
    version = DTLS_VERSION_1_2,
    epoch = 0,
    seq_no = seq_no,
    length = 0,
  };
}

dtls_handshake_header_default :: (kind: DTLS_Handshake_Kind, message_seq: u16) -> DTLS_Handshake_Header {
  return .{
  kind = kind,
  length = 0,
  message_seq = message_seq,
  fragment_offset = 0,
  fragment_length = 0,
  };
}
dtls_message_client_hello :: (ctx: *DTLS_Context, client_hello: DTLS_Handshake_Message, cookie: []u8) -> DTLS_Handshake_Message {
}

dtls_message_hello_verify :: (ctx: *DTLS_Context, client_hello: DTLS_Handshake_Message, cookie: []u8) -> DTLS_Handshake_Message {
  record := dtls_handsake_record_default(client_hello.record.seq_no);
  record.length = cast(u16)(DTLS_HANDSHAKE_HEADER_SIZE + dtls_message_get_size(DTLS_Hello_Verify, cookie));
  header := dtls_handshake_header_default(.HELLO_VERIFY_REQUEST, ctx.seq_no.second);
  header.fragment_length = record.length - DTLS_HANDSHAKE_HEADER_SIZE;
  header.length = record.length - DTLS_HANDSHAKE_HEADER_SIZE;

  value: DTLS_Handshake_Value;
  hello_verify := DTLS_Hello_Verify.{ cookie = cookie };
  set(*value, hello_verify);

  msg := DTLS_Handshake_Message.{
    record = record,
    header = header,
    value = value,
  };
  return msg;
}

_get_supported_cipher_suite :: (halo: DTLS_Client_Hello) -> bool, DTLS_Cipher_Suite {
  for cipher : DTLS_SUPPORTED_CIPHER_SUITES {
    for halo.cipher_suites {
      if it == cipher return true, it;
    }
  }
  return false, .{};
}

dtls_message_server_hello :: (ctx: *DTLS_Context, client_hello: DTLS_Handshake_Message, exts: []DTLS_Extension) -> DTLS_Handshake_Message {
  record := dtls_handsake_record_default(ctx.seq_no);
  record.length = cast(u16)(DTLS_HANDSHAKE_HEADER_SIZE + dtls_message_get_size(DTLS_Server_Hello, cast([]u8)"", exts));
  header := dtls_handshake_header_default(.SERVER_HELLO, ctx.seq_no.second);
  header.fragment_length = record.length - DTLS_HANDSHAKE_HEADER_SIZE;
  header.length = record.length - DTLS_HANDSHAKE_HEADER_SIZE;

  client_hello_value := isa(client_hello.value, DTLS_Client_Hello);
  ok, suite := _get_supported_cipher_suite(client_hello_value);
  if !ok {
    log_err("we only support % cipher\n", TLS_RSA_WITH_AES_128_CBC_SHA);
    log_err("given ciphers:\n%\n", client_hello_value.cipher_suites);
    assert(false, "unreachable");
  }

  value: DTLS_Handshake_Value;
  server_hello := DTLS_Server_Hello.{
    server_version = DTLS_VERSION_1_2,
    random = DTLS_Random.{ _get_gm_time(), random_n_bytes(28) },
    cipher_suite = TLS_RSA_WITH_AES_128_CBC_SHA,
    compression_method = .NULL,
    extensions = exts,
  };
  print("this is what we generated %\n",hex_string(server_hello.random.random_bytes));
  set(*value, server_hello);

  msg := DTLS_Handshake_Message.{
    record = record,
    header = header,
    value = value,
  };
  ctx.seq_no += 1;
  return msg;
}

dtls_message_server_hello_done :: (ctx: *DTLS_Context) -> DTLS_Handshake_Message {
  record := dtls_handsake_record_default(ctx.seq_no);
  record.length = cast(u16)DTLS_HANDSHAKE_HEADER_SIZE;
  header := dtls_handshake_header_default(.SERVER_HELLO_DONE, ctx.seq_no.second);
  header.fragment_length = record.length - DTLS_HANDSHAKE_HEADER_SIZE;
  header.length = record.length - DTLS_HANDSHAKE_HEADER_SIZE;

  value: DTLS_Handshake_Value;
  server_hello_done := DTLS_Server_Hello_Done.{};
  set(*value, server_hello_done);

  msg := DTLS_Handshake_Message.{
    record = record,
    header = header,
    value = value,
  };
  ctx.seq_no += 1;
  return msg;
}

dtls_message_get_cookie :: (msg: DTLS_Handshake_Message) -> bool, []u8 {
  if msg.header.kind == {
    case .CLIENT_HELLO; {
      as_hello := isa(*msg.value, DTLS_Client_Hello); assert(as_hello != null);
      return as_hello.cookie.count != 0, as_hello.cookie;
    }
    case; assert(false, "unimplemented!");
  }
  return false, .[];
}

// @todo implement this
// as this is a server side cookie we kinda don't give a shit about it right now
// we should probably implement this
dtls_generate_cookie :: () -> []u8 {
  // @leak
  temp: []u8 = xx alloc_string(32);
  random_bytes(*temp);
  return temp;
// parameters version, random, session_id, cipher_suites, compression_method
// Cookie = HMAC(Secret, Client-IP, Client-Parameters)
}

f :: (writer: *Bytes_Writer, x: Any, size_notes_ommitable := false, caller_loc := #caller_location){
  assert(x.type.type == .STRUCT);
  x_type := cast(*Type_Info_Struct)x.type;
  
  for x_type.members {
    start := writer.cursor;
    if equal(it.name, "_") continue;
    notes := it.notes;
    
    if it.type.type == .STRUCT {
      as_any: Any;
      as_any.type = it.type.(*Type_Info_Struct);
      as_any.value_pointer = x.value_pointer + it.offset_in_bytes;
      omit_size := ifx has_note(it.notes, "DefaultSize") true else false;
      f(writer, as_any, omit_size);
      continue;
    }
    if size_notes_ommitable != true {
      assert(notes.count != 0, tprint("struct '%' field '%' has no notes, cannot serialize!", x_type.name, it.name));
    }

    sz := ifx notes.count == 0 || has_note(notes, "DefaultSize") it.type.runtime_size else string_to_int(notes[1]);
    assert(sz != -1);


    if has_note(notes, "Size") || notes.count == 0 || has_note(notes, "DefaultSize") {
      if sz == {
        case 1; write_bytes(writer, (x.value_pointer + it.offset_in_bytes).(*u8).*);
        case 2; write_bytes(writer, (x.value_pointer + it.offset_in_bytes).(*u16).*);
        case 4; write_bytes(writer, (x.value_pointer + it.offset_in_bytes).(*u32).*);
        case 8; write_bytes(writer, (x.value_pointer + it.offset_in_bytes).(*u64).*);
        case; unreachable("size % cannot be converted to int for struct field %.%", sz, x_type.name, it.name);
      }
    } else if has_note(notes, "Vla") {
      if it.type.type != .ARRAY {
        unreachable("Vla needs to be array provided % for %.%\n", it.type.type, x_type.name, it.name);
      }
      vla_array_info := it.type.(*Type_Info_Array);
      vla_array_count, vla_array_data := get_array_count_and_data(x.value_pointer.(*u8) + it.offset_in_bytes, vla_array_info);

      sz := string_to_int(notes[1]);
      as_byte_slice := (x.value_pointer.(*u8) + it.offset_in_bytes).(*[]u8).*;
      inner_type := vla_array_info.element_type;
      inner_type_size := inner_type.runtime_size;

      if inner_type.type == .STRUCT {
        arg_array: [..]Any;
        for nth_struct_idx: 0..vla_array_count-1 {
          for member: inner_type.(*Type_Info_Struct).members {
            if !has_note(member.notes, "Vla") continue;
            as_any: Any;
            nth_struct := vla_array_data + nth_struct_idx * inner_type.(*Type_Info_Struct).runtime_size;
            as_any.type = member.type;
            as_any.value_pointer = nth_struct + member.offset_in_bytes;
            array_add(*arg_array, as_any);
          }
        }
        inner_type_size = dtls_message_get_size_runtime(inner_type.(*Type_Info_Struct), arg_array);
      }
      assert(inner_type_size != -1);
      if sz == {
        case 1; write_bytes(writer, cast(u8) (as_byte_slice.count * inner_type_size));
        case 2; write_bytes(writer, cast(u16)(as_byte_slice.count * inner_type_size));
        case 4; write_bytes(writer, cast(u32)(as_byte_slice.count * inner_type_size));
        case 8; write_bytes(writer, cast(u64)(as_byte_slice.count * inner_type_size));
        case; unreachable("size % cannot be converted to int for struct field %.%", sz, x_type.name, it.name);
      }
      if inner_type.type == .STRUCT {
        omit_size := ifx has_note(it.notes, "DefaultSize") true else false;
        for 0..vla_array_count-1 {
          as_any: Any;
          as_any.type = inner_type;
          as_any.value_pointer = vla_array_data + it * inner_type_size;
          f(writer, as_any, omit_size);
        }
      } else {
        write_string(writer, cast(string) as_byte_slice);
      }
    } else if has_note(notes, "Array") {
      data_ptr := x.value_pointer.(*u8) + it.offset_in_bytes;
      if it.type.type == .INTEGER {
        for 0 .. sz-1 {
          write_bytes(writer,  (data_ptr +  sz - 1 - it).(*u8).* & 0xff);
        }
      } else if it.type.type == .ARRAY {
        as_array_type_info := it.type.(*Type_Info_Array);
        count, data := get_array_count_and_data(x.value_pointer.(*u8) + it.offset_in_bytes, as_array_type_info);
        as_byte_slice: []u8;
        as_byte_slice.data = data;
        as_byte_slice.count = sz;
        write_string(writer, xx as_byte_slice);
      }
    } else {
        unreachable("Invalid Directive for \"%\" for %.%", notes[0], x_type.name, it.name);
    }
    end := writer.cursor;
  }
}
dtls_message_serialize :: (msg: *DTLS_Handshake_Message) -> []u8 {
  total_length := DTLS_RECORD_SIZE + msg.record.length;
  serialized: []u8 = xx alloc_string(total_length);
  writer := Bytes_Writer.{
    cursor = 0,
    bytes = serialized,
    should_swap = true,
  };
  f(*writer, msg.record);

  f(*writer, msg.header);

  value_as_any: Any;
  value_as_any.type = msg.value.tag.(*Type_Info);
  value_as_any.value_pointer = msg.value.bytes.data;
  f(*writer, value_as_any);

  return writer.bytes;
}

has_note :: (haysack: []string, needle: string) -> bool {
  for haysack if equal(it, needle) return true;
  return false;
}

_message_size_calc :: (struct_info: *Type_Info_Struct, caller_loc: Source_Code_Location, zero_vla := false) -> s64, s64 {
  sz := 0;
  n_vlas := 0;
  for struct_info.members {
    assert(it.notes.count != 0, tprint("struct '%' field '%' has no notes cannot generate size!", struct_info.name, it.name));

    if has_note(it.notes, "Size") || has_note(it.notes, "Array") {
      sz += string_to_int(it.notes[1]);
    } else if has_note(it.notes, "DefaultSize") {
      size := it.type.runtime_size; assert(size != -1);
      sz += size;
    } else if has_note(it.notes, "InnerSize") {
      if it.type.type != .STRUCT {
        unreachable("Invalid Directive for %.% \"InnerSize\" is only applicable to structures!", struct_info.name, it.name);
      }
      as_struct := it.type.(*Type_Info_Struct);
      size_field := get_field(as_struct, "_");
      if size_field == null {
        unreachable(
          "error getting size for %.%! We do not implement recursive calcuation of sizes! please add a field _:void; @Size in struct l%",
          struct_info.name, it.name, as_struct.name);
      }
      size := string_to_int(size_field.notes[1]); assert(size > 0);
      sz += size;
    } else if has_note(it.notes, "Vla") {
      sz += string_to_int(it.notes[1]);
      n_vlas += 1;
    } else {
      assert(false, tprint("get_size for % is not implemented!", it.notes));
    }
  }
  using caller_loc;
  if zero_vla assert(n_vlas == 0, tprint(
    "struct % has % VLAs but none provided!\ncalled from %:%:%",
    struct_info.name ,n_vlas, fully_pathed_filename, line_number, character_number));
  return sz, n_vlas;
}

dtls_message_get_size_runtime :: (msg_type: *Type_Info_Struct, values: []Any, $loc := #caller_location) -> s64 {
  sz, n_vlas := _message_size_calc(msg_type, loc);

  for values {
    assert(it.type.type == .ARRAY, "VLAs are array bruh...");
    as_array := it.type.(*Type_Info_Array);
    element_type := as_array.element_type;
    if element_type.type == {
      case .INTEGER;
        count := get_array_count_and_data(it.value_pointer, as_array);
        elem_size := element_type.runtime_size; assert(elem_size != -1);
        sz += count * elem_size;
      case .STRUCT; assert(false, "refection in refection is crazy bru");
      case; assert(false, "what %:%\n",element_type.*, as_array.element_type.type);
    }
  }
  return sz;
}

dtls_message_get_size :: ($msg_type: Type, $loc := #caller_location) -> s64 {
  sz, n_vlas := #run _message_size_calc(cast(*Type_Info_Struct)msg_type, loc);
  return sz;
}
dtls_message_get_size :: ($msg_type: Type, values: ..Any, $loc := #caller_location) -> s64 {
  sz, n_vlas := #run _message_size_calc(cast(*Type_Info_Struct)msg_type, loc);

  for any_value: values {
    assert(any_value.type.type == .ARRAY, "VLAs are array bruh...");
    as_array := any_value.type.(*Type_Info_Array);
    element_type := as_array.element_type;
    if element_type.type == {
      case .INTEGER;
        count := ifx as_array.array_type == .FIXED as_array.array_count
                 else any_value.value_pointer.(*[]u8).*.count;
        elem_size := element_type.runtime_size; assert(elem_size != -1);
        sz += count * elem_size;
      case .STRUCT;
        struct_type := element_type.(*Type_Info_Struct);
        count, data := get_array_count_and_data(any_value.value_pointer, as_array);
        arg_array: [..]Any;
        for nth_struct_idx: 0..count-1 {
          for member: struct_type.members {
            if !has_note(member.notes, "Vla") continue;
            as_any: Any;
            nth_struct := data + nth_struct_idx * struct_type.runtime_size;
            as_any.type = member.type;
            as_any.value_pointer = nth_struct + member.offset_in_bytes;
            array_add(*arg_array, as_any);
          }
          runtime_sz := dtls_message_get_size_runtime(struct_type, arg_array);
          sz += runtime_sz;
          array_reset_keeping_memory(*arg_array);
        }
      case; print("what %:%\n",element_type.*, as_array.element_type.type);
    }
  }
  // can we do this on comptime??
  if values.count != n_vlas
    assert(false, tprint("struct % has % VLAs but % provided!",msg_type ,n_vlas, values.count));

  // for values sz += it.value_pointer(*).count * size_of(type_of(it.data.*));
  return sz;
}


#scope_file
#import "utils";
#import "Tagged_Union";
#import "Basic";
#import "Random";
#import "POSIX";
#import "Compiler";
#import "Log";
#import "String";
#import "Reflection";
