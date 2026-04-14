DTLS_VERSION_1_2 :: DTLS_Protocol_Version.{0xfe, 0xfd}; // dtls version 1.2

DTLS_Context :: struct {
};

DTLS_Protocol_Version :: struct {
  major: u8;
  minor: u8;
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
  HELLO_VERIFY_REQUEST  ::   03;
  CERTIFICATE           ::   11;
  SERVER_KEY_EXCHANGE   ::   12;
  CERTIFICATE_REQUEST   ::   13;
  SERVER_HELLO_DONE     ::   14;
  CERTIFICATE_VERIFY    ::   15;
  CLIENT_KEY_EXCHANGE   ::   16;
  FINISHED              ::   20;
};

DTLS_Random :: struct {
  gmt_unix_time: u32;
  random_bytes: [28]u8;
};

DTLS_Compression_Method :: enum u8 {
  NULL :: 0;
};
DTLS_Cypher_Suite :: [2]u8;


// this is the plain text thingy but idk we need anything more than this as we only
// use dtls for key exchange
DTLS_Record :: struct {
  kind: DTLS_Content_Kind;
  version: DTLS_Protocol_Version;
  epoch: u16;
  sequence_number: Pair(u32, u16);
  length: u16; // length of the Handshake header + value
};

DTLS_RECORD_SIZE :: 13;

DTLS_Handshake_Header :: struct {
  kind: DTLS_Handshake_Kind;
  length: u32;                  // u24
  message_seq: u16;
  fragment_offset: u32;         // u24
  fragment_length: u32;         // u24
};
DTLS_HANDSHAKE_HEADER_SIZE :: 12;

DTLS_Client_Hello :: struct {
  client_version: DTLS_Protocol_Version;
  random: DTLS_Random;
  // variable lengthed idk how that works
  session_id: []u8;  // 0..32 lengthed
  cookie: []u8; // 0..255 lengthed
  cipher_suites: []DTLS_Cypher_Suite; // 32k - 1 words,  64k - 2 bytes
  compression_methods: []DTLS_Compression_Method;  // 255 max
};

DTLS_Hello_Verify :: struct {
  server_version: DTLS_Protocol_Version = .{0xfe, 0xff}; // should be 1.0
  cookie: []u8;  // 0..255
};

dtls_hello_verify_size :: (cookie_length: s64) -> s64 #expand {
  return size_of(DTLS_Protocol_Version) + 1 + cookie_length;
}

DTLS_Handshake_Value :: Tagged_Union(
  DTLS_Client_Hello,
  DTLS_Hello_Verify,
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
  seq_hi := r.sequence_number.first;
  seq_lo := r.sequence_number.second;
  print_to_builder(*sb, "%DTLS_Record {\n", tab);
  print_to_builder(*sb, "%  kind: %\n", tab, r.kind);
  print_to_builder(*sb, "%  version: %.%\n", tab, ~r.version.major, ~r.version.minor);
  print_to_builder(*sb, "%  epoch: %\n", tab, r.epoch);
  print_to_builder(*sb, "%  sequence_number: (%, %)\n", tab, seq_hi, seq_lo);
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
  sequence_number: Pair(u32, u16);
  sequence_number.first = read_bytes(reader, u32);
  sequence_number.second = read_bytes(reader, u16);

  version := DTLS_Protocol_Version.{
    major = version_hi,
    minor = version_lo,
  };

  length := read_bytes(reader, u16);
  return .{
    kind = xx kind,
    version = version,
    epoch = epoch,
    sequence_number = sequence_number,
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
  cipher_suites: [..]DTLS_Cypher_Suite;

  // @leak this should be on temporary allocator in peer context or something bru
  array_reserve(*cipher_suites, cipher_suite_length);
  for 0..cipher_suite_length-1 {
    cipher_hi := read_bytes(reader, u8);
    cipher_lo := read_bytes(reader, u8);
    array_add(*cipher_suites, .[cipher_hi, cipher_lo]);
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

_dtls_record_serialize :: (writer: *Bytes_Writer, record: *DTLS_Record) {
  write_bytes(writer, record.kind);
  write_bytes(writer, record.version.major);
  write_bytes(writer, record.version.minor);
  write_bytes(writer, record.epoch);
  write_bytes(writer, record.sequence_number.first);
  write_bytes(writer, record.sequence_number.second);
  write_bytes(writer, record.length);
}

_dtls_handshake_header_serialize :: (writer: *Bytes_Writer, header: *DTLS_Handshake_Header) {
  length_as_bytes := int_to_bytes(3, header.length);
  fragment_offset_as_bytes := int_to_bytes(3, header.fragment_offset);
  fragment_length_as_bytes := int_to_bytes(3, header.fragment_length);

  write_bytes(writer, header.kind);
  write_string(writer, xx length_as_bytes);
  write_bytes(writer, header.message_seq);
  write_string(writer, xx fragment_offset_as_bytes);
  write_string(writer, xx fragment_length_as_bytes);
}
_dtls_hello_client_serialize :: (writer: *Bytes_Writer, value: *DTLS_Handshake_Value){
  assert(false, "unimplemented!");
}
_dtls_dtls_hello_verify_serialize :: (writer: *Bytes_Writer, value: *DTLS_Hello_Verify) {
  write_bytes(writer, value.server_version.major);
  write_bytes(writer, value.server_version.minor);
  assert(value.cookie.count != 0);
  write_bytes(writer, cast(u8)value.cookie.count);
  assert(value.cookie.count > 0);
  if value.cookie.count > 0 {
    write_string(writer, cast(string)value.cookie);
  }
}
_dtls_handshake_value_serialize :: (writer: *Bytes_Writer, value: *DTLS_Handshake_Value) {
  as_client_hello := isa(value, DTLS_Hello_Verify);
  assert(as_client_hello != null);
  _dtls_dtls_hello_verify_serialize(writer, as_client_hello);
}

dtls_message_serialize :: (msg: *DTLS_Handshake_Message) -> []u8 {
  total_length := DTLS_RECORD_SIZE + msg.record.length;
  serialized: []u8 = xx alloc_string(total_length);
  writer := Bytes_Writer.{
    cursor = 0,
    bytes = serialized,
    should_swap = true,
  };
  _dtls_record_serialize(*writer, *msg.record);
  _dtls_handshake_header_serialize(*writer, *msg.header);
  _dtls_handshake_value_serialize(*writer, *msg.value);
  return serialized;
}

dtls_handsake_record_default :: (seq_no: Pair(u32,u16)) -> DTLS_Record {
  return .{
    kind = .HANDSHAKE,
    version = DTLS_VERSION_1_2,
    epoch = 0,
    sequence_number = seq_no,
    length = 0,
  };
}

dtls_handshake_header_default :: (kind: DTLS_Handshake_Kind) -> DTLS_Handshake_Header {
  return .{
  kind = kind,
  length = 0,
  message_seq = 0,
  fragment_offset = 0,
  fragment_length = 0,
  };
}

dtls_message_hello_verify :: (ctx: *DTLS_Context, client_hello: DTLS_Handshake_Message, cookie: []u8) -> DTLS_Handshake_Message {
  record := dtls_handsake_record_default(client_hello.record.sequence_number);
  record.length = cast(u16)(DTLS_HANDSHAKE_HEADER_SIZE + dtls_hello_verify_size(cookie.count));
  assert(record.length == 47);
  header := dtls_handshake_header_default(.HELLO_VERIFY_REQUEST);
  header.fragment_length = record.length - DTLS_HANDSHAKE_HEADER_SIZE;
  header.length = record.length - DTLS_HANDSHAKE_HEADER_SIZE;
  assert(header.length == 35);

  value: DTLS_Handshake_Value;
  hello_verify := DTLS_Hello_Verify.{ server_version = DTLS_VERSION_1_2, cookie = cookie };
  set(*value, hello_verify);

  msg := DTLS_Handshake_Message.{
    record = record,
    header = header,
    value = value,
  };
  return msg;
}

// @todo implement this
// as this is a server side cookie we kinda don't give a shit about it right now as
// the other peer won't care too but we should probably implement this
dtls_generate_cookie :: () -> []u8 {
  // @leak
  temp: []u8 = xx alloc_string(32);
  random_bytes(*temp);
  return temp;
// parameters
// version, random, session_id, cipher_suites,
//    compression_method
//     Cookie = HMAC(Secret, Client-IP, Client-Parameters)
}


#scope_file
#import "utils";
#import "Tagged_Union";
#import "Basic";
#import "Random";
