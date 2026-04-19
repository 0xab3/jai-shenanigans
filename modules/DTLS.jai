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
  HELLO_REQUEST         ::   00; @DTLS_Client_Hello
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

_deserialize :: (reader: *Bytes_Reader, x: *Any, size_notes_ommitable := false, caller_loc := #caller_location) {
  if x.type.(*Type_Info).type != .STRUCT assert(false,"panic!!");
  x_type := cast(*Type_Info_Struct)x.type; 

  for x_type.members {
    if equal(it.name, "_") continue;
    notes := it.notes;

    if it.type.type == .STRUCT {
      omit_size := ifx has_note(it.notes, "DefaultSize") true else false;
      as_any: Any;
      as_any.type = it.type;
      as_any.value_pointer = x.value_pointer.(*u8) + it.offset_in_bytes;
      _deserialize(reader, *as_any, omit_size);
      continue;
    }

    if size_notes_ommitable != true {
      assert(notes.count != 0, tprint("struct '%' field '%' has no notes, cannot serialize!", x_type.name, it.name));
    }

    sz := ifx notes.count == 0 || has_note(notes, "DefaultSize") it.type.runtime_size else string_to_int(notes[1]);
    assert(sz != -1);

    if has_note(notes, "Size") || notes.count == 0 || has_note(notes, "DefaultSize")  {
      if sz == {
        case 1; read_bytes_inplace(reader, (x.value_pointer + it.offset_in_bytes).(*u8));
        case 2; read_bytes_inplace(reader, (x.value_pointer + it.offset_in_bytes).(*u16));
        case 4; read_bytes_inplace(reader, (x.value_pointer + it.offset_in_bytes).(*u32));
        case 8; read_bytes_inplace(reader, (x.value_pointer + it.offset_in_bytes).(*u64));
        case; unreachable("size % cannot be converted to int for struct field %.%", sz, x_type.name, it.name);
      }
    } else if has_note(notes, "Vla") {
      if it.type.type != .ARRAY {
        unreachable("Vla needs to be array provided % for %.%\n", it.type.type, x_type.name, it.name);
      }

      vla_array_info := it.type.(*Type_Info_Array);
      array_start_ptr := x.value_pointer.(*u8) + it.offset_in_bytes;

      inner_type := vla_array_info.element_type;
      inner_type_size := inner_type.runtime_size;


      read_sz := string_to_int(notes[1]);
      sz := 0;
      if read_sz == {
        case 1; read_bytes_inplace(reader, (*sz).(*u8));
        case 2; read_bytes_inplace(reader, (*sz).(*u16));
        case 4; read_bytes_inplace(reader, (*sz).(*u32));
        case 8; read_bytes_inplace(reader, (*sz).(*u64));
        case; unreachable("size % cannot be converted to int for struct field %.%", sz, x_type.name, it.name);
      }
      read_array: [..]Any;
      read_array.allocator = temp;

      if it.type.type == .STRUCT {
        bytes_read := 0;
        count := 0;
        while bytes_read < sz {
          as_any: Any;
          as_any.type = it.type;
          as_any.value_pointer = talloc(inner_type_size);

          omit_size := ifx has_note(it.notes, "DefaultSize") true else false;
          start := reader.cursor;
          read_struct := _deserialize(reader, *as_any, omit_size);
          array_add(*read_array, read_struct); 
          end := reader.cursor;
          bytes_read += end - start;
          count += 1;
        }
        // malformed packet
        print("read % bytes while sz was %\n", bytes_read, sz);
        if bytes_read > sz unreachable("oh healll nawww!");
        vla_as_array := array_start_ptr.(*[]u8);
        vla_as_array.count = read_array.count;

        // @leak
        reflection_array: [..]u8;
        for read_array {
          reflection_array_add(*reflection_array, it.value_pointer, it.type);
        }
        vla_as_array.data = reflection_array.data;

      } else {
        // @leak
        str := xx copy_string(xx read_string_no_copy(reader,  sz));
        vla_as_array := array_start_ptr.(*[]u8);
        vla_as_array.data = str.data;
        vla_as_array.count = sz / inner_type.runtime_size;
      }
    } else if has_note(notes, "Array") {
      view := read_string_no_copy(reader, sz);
      data_ptr := x.value_pointer.(*u8) + it.offset_in_bytes;
      if it.type.type == .INTEGER {
        memcpy(data_ptr + it.type.runtime_size - sz, view.data, sz);
        byte_swap_inplace(data_ptr, it.type.runtime_size);
      } else if it.type.type == .ARRAY {
        as_array_type_info := it.type.(*Type_Info_Array);
        array_kind := as_array_type_info.array_type;
        if array_kind == .FIXED unreachable("only fixed array is supported given % in %.%\n",array_kind, x_type.name, it.name);

        count, data := get_array_count_and_data(x.value_pointer.(*u8) + it.offset_in_bytes, as_array_type_info);
        assert(count >= sz, tprint("array_count % is less than @Size % for %.%\n", count, sz, x_type.name, it.name));
        memcpy(data, view.data, sz);
      }

    } else {
      unreachable("failed to deserialize message %.% has unknown notes %!\n", x_type.name, it.name, notes);
    }
  }
}


dtls_message_deserialize :: (buf: []u8) -> DTLS_Handshake_Message {
  reader := Bytes_Reader.{ bytes = buf };
  record: DTLS_Record;
  hdr: DTLS_Handshake_Header;
  verify: DTLS_Hello_Verify;
  value: DTLS_Handshake_Value;
  _deserialize(*reader, *to_any(*record));
  _deserialize(*reader, *to_any(*hdr));
  _deserialize(*reader, *to_any(*verify));
  set(*value, verify);
  return .{
    record = record,
    header = hdr,
    value = value,
  };

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

_serialize :: (writer: *Bytes_Writer, x: Any, size_notes_ommitable := false, caller_loc := #caller_location){
  assert(x.type.type == .STRUCT);
  x_type := cast(*Type_Info_Struct)x.type;
  
  for x_type.members {
    if equal(it.name, "_") continue;
    notes := it.notes;
    
    if it.type.type == .STRUCT {
      as_any: Any;
      as_any.type = it.type.(*Type_Info_Struct);
      as_any.value_pointer = x.value_pointer + it.offset_in_bytes;
      omit_size := ifx has_note(it.notes, "DefaultSize") true else false;
      _serialize(writer, as_any, omit_size);
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
          _serialize(writer, as_any, omit_size);
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
  _serialize(*writer, msg.record);
  _serialize(*writer, msg.header);

  value_as_any: Any;
  value_as_any.type = msg.value.tag.(*Type_Info);
  value_as_any.value_pointer = msg.value.bytes.data;
  _serialize(*writer, value_as_any);

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
    assert(false, tprint("struct % has % VLAs but % provided!", msg_type, n_vlas, values.count));

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
