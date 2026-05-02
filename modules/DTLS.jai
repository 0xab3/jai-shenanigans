DTLS_VERSION_1_2 :: DTLS_Protocol_Version.{0xfe, 0xfd}; // we only support 1.2
DTLS_VERSION_1_0 :: DTLS_Protocol_Version.{0xfe, 0xff};

// TLS_RSA_WITH_AES_128_CBC_SHA             ::  DTLS_Cipher_Suite.{0x00,   0x2f};
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  ::  DTLS_Cipher_Suite.{0xc0,   0x2b};
// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256    ::  DTLS_Cipher_Suite.{0xc0,   0x2f};
// TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA     ::  DTLS_Cipher_Suite.{0xc0,   0x0a};
// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA       ::  DTLS_Cipher_Suite.{0xc0,   0x14};
// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  ::  DTLS_Cipher_Suite.{0xc0,   0x2c};
// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384    ::  DTLS_Cipher_Suite.{0xc0,   0x30};



DTLS_SUPPORTED_CIPHER_SUITES :: DTLS_Cipher_Suite.[
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
];

DTLS_SUPPORTED_COMPRESSION_METHODS :: DTLS_Compression_Method.[
  .NULL
];

// @todo create fingerprint here for sdp
DTLS_CERTIFICATE :: #run () -> DTLS_Certificate {
  filename := "cert.der";
  contents, ok := read_entire_file(filename);
  assert(ok, tprint("failed to read file %",ok));
  return .{
    cert = xx contents,
  };

}();

dtls_certificate_private_key :: (ctx: *DTLS_Context) -> Crypto_Key {
  if ctx.local_cert_privkey.key == null {
    filename := temp_c_string("key.der");
    fp := fopen(filename, "r");
    assert(fp != null);
    pkey := d2i_PrivateKey_fp(fp, null);
    assert(pkey != null);
    ctx.local_cert_privkey = .{pkey};
  }
  return ctx.local_cert_privkey;
}

DTLS_CERTIFICATES :: DTLS_Certificate.[DTLS_CERTIFICATE];

DTLS_Message_Raw :: struct {
  size: s64;
  entire: []u8;
  record: []u8;
  header: []u8;
  payload: []u8;
}

DTLS_Context :: struct {
  role: enum {CLIENT; SERVER;};
  flight: u8 = 1;
  cookie: []u8;
  epoch: u16;
  seq_no: Pair(u32, u16);
  local_cert : DTLS_Certificate;
  local_cert_privkey: Crypto_Key;
  remote_cert: DTLS_Certificate;
  ctx_random: DTLS_Random;
  remote_last_random: DTLS_Random; // we need this for signature validation

  session_keying_material: Epheremal_Key;
  key_block: DTLS_Key_Block;
  flight4_messages: [..]DTLS_Message_Raw; // technically only flight4 messages

  state: enum { IN_PROGRESS; FINISHED; } = .IN_PROGRESS;
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
#assert size_of(DTLS_Cipher_Suite) == 2;

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

DTLS_Key_Block :: struct {
  // client_write_mac_key: []u8; // unused
  // server_write_mac_key: []u8; // unused
  client_write_key: []u8; // 16
  server_write_key: []u8; // 16
  client_write_IV : []u8; // 4
  server_write_IV : []u8; // 4
  entire: []u8; // dynamic ig?
}

// @todo this is not generic at all
DTLS_AEAD_Cipher :: struct {
  nonce_explicit: []u8; @Array @8 // AES_GCM_IV_SIZE but we only need the explicit part
  content: []u8; @Vla @0
};

// @todo this should have multiple ciphers not just stream cipher
DTLS_Cipher_Text :: struct {
  record: DTLS_Record;
  aead: DTLS_AEAD_Cipher;
};
DTLS_Cipher_Temp :: struct {
  header: DTLS_Handshake_Header; @InnerSize
  content: []u8; @Vla @0
}

DTLS_RECORD_SIZE :: #run dtls_message_get_size(DTLS_Record);
#assert DTLS_RECORD_SIZE == 13;

DTLS_Handshake_Header :: struct {
  _:void; @Size @12
  kind: DTLS_Handshake_Kind; @DefaultSize
  length: u32; @Array @3
  message_seq: u16; @DefaultSize
  fragment_offset: u32; @Array @3
  fragment_length: u32; @Array @3
};
DTLS_HANDSHAKE_HEADER_SIZE :: #run dtls_message_get_size(DTLS_Handshake_Header);
#assert DTLS_HANDSHAKE_HEADER_SIZE == 12;

DTLS_Client_Hello :: struct {
  client_version := DTLS_VERSION_1_2; @InnerSize
  random: DTLS_Random; @InnerSize
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

DTLS_Hash_Algorithm :: enum u8 {
  NONE    ::  0;
  MD5     ::  1;
  SHA1    ::  2;
  SHA224  ::  3;
  SHA256  ::  4;
  SHA384  ::  5;
  SHA512  ::  6;
};

DTLS_Signature_Algorithm :: enum u8 {
  ANONYMOUS  ::  0;
  RSA        ::  1;
  DSA        ::  2;
  ECDSA      ::  3;
};

// @todo fix this
DTLS_Signature_Hash_Algorithm :: struct {
  _: void; @Size @2
  high: u8; @DefaultSize
  low: u8; @DefaultSize
};

DTLS_Signature_Hash_Algorithms :: struct {
  algos: []DTLS_Signature_Hash_Algorithm; @Vla @2

};
SIGNATURE_ALGORITHM_RSA_PKCS1_SHA256 :: DTLS_Signature_Hash_Algorithm.{ 0x04, 0x01 };
SIGNATURE_ALGORITHM_ED25519 :: DTLS_Signature_Hash_Algorithm.{ 0x08, 0x07 };
SIGNATURE_ALGORITHM_ECDSA_SECP256R1_SHA256 :: DTLS_Signature_Hash_Algorithm.{0x04, 0x03};


DTLS_ECCurveType :: enum u8 {
  EXPLICIT_PRIME  :: 1;
  EXPLICIT_CHAR2  :: 2;
  NAMED_CURVE     :: 3;
};

DTLS_ECNamedCurve :: enum u16 {
  X25519 :: 0x1d;
};

// @todo @priority @bug this hardcodes the length of public key
// we need to implement recursive size calculation for @InnerSize 
// instead using _:void; for size
DTLS_ECDHEKey_Params :: struct {
  _: void; @Size @36 
  type: DTLS_ECCurveType; @DefaultSize
  name: DTLS_ECNamedCurve; @DefaultSize
  public_key: []u8; @Vla @1
};
DTLS_ECDSignature_Algorithm :: struct {
  hash_algo: u8; @DefaultSize
  hash_sign: u8; @DefaultSize
  signature: []u8; @Vla @2
};

DTLS_ECDHParams :: struct {
  key_params: DTLS_ECDHEKey_Params; @InnerSize
  hash_algorithm: DTLS_ECDSignature_Algorithm; @InnerSize
};


DTLS_Server_Hello :: struct {
  server_version := DTLS_VERSION_1_0; @InnerSize
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
  server_version: DTLS_Protocol_Version = DTLS_VERSION_1_0; @InnerSize
  cookie: []u8;  @Vla @1
};

DTLS_Server_Hello_Done :: struct {};
DTLS_Hello_Request :: struct {};

DTLS_Certificate :: struct {
  cert :[]u8; @Vla @3
};

Epheremal_Key :: struct {
  using #as ours: Asymmetric_Key; // @todo remove the using shit
  remote_public_key: []u8;
  master_key: []u8;
};

Asymmetric_Key :: struct {
  key: *EVP_PKEY;
  public_key: []u8; // serialized
};

Crypto_Key :: struct {
  key: *EVP_PKEY;
};


DTLS_Certificate_List :: struct {
  certs: []DTLS_Certificate; @Vla @3
}
// DTLS_Server_Key_Exchange :: struct {
//   select (KeyExchangeAlgorithm) {
//     case dh_anon:
//     ServerDHParams params;
//     case dhe_dss:
//     case dhe_rsa:
//     ServerDHParams params;
//     digitally-signed struct {
//       opaque client_random[32];
//       opaque server_random[32];
//       ServerDHParams params;
//     } signed_params;
//     case rsa:
//     case dh_dss:
//     case dh_rsa:
//     struct {} ;
//     /* message is omitted for rsa, dh_dss, and dh_rsa */
//     /* may be extended, e.g., for ECDH -- see [TLSECC] */
//   };
// } ;

DTLS_Client_Key_Exchange :: struct {
  ecdh_Yc: []u8; @Vla @1
};

DTLS_Certificate_Verify :: struct {
  sign_algo: DTLS_Signature_Hash_Algorithm; @InnerSize
  signature: []u8; @Vla @2
}

DTLS_Change_Cipher_Spec :: struct {
  inner: u8 = 1; @DefaultSize
}

DTLS_Message_Finish :: struct {
  verify_data: []u8; @Array @12
};

DTLS_Handshake_Value :: Tagged_Union(
  DTLS_Hello_Request,
  DTLS_Client_Hello,
  DTLS_Hello_Verify,
  DTLS_Server_Hello,
  DTLS_Certificate_Verify,
  DTLS_Change_Cipher_Spec,
  DTLS_Message_Finish,
  DTLS_Server_Hello_Done,
);


DTLS_Handshake_Message :: struct {
  record: DTLS_Record;
  header: DTLS_Handshake_Header;
  value: DTLS_Handshake_Value;
};

#run {
  contents, ok := read_entire_file("cert.der"); assert(ok);
  fp := dtls_certificate_create_fingerprint(.{ xx contents });
  print("%\n", fp);
}

dtls_get_finish_label :: (ctx: *DTLS_Context) -> string {
  if ctx.role == .CLIENT return "client finished";
  return "server finished";
  
}
dtls_get_session_keying_material :: (ctx: *DTLS_Context) -> Epheremal_Key {
  if ctx.session_keying_material.key == null {
    ctx.session_keying_material.key = generate_ephemeral_ec_key();
    ctx.session_keying_material.public_key = evp_key_serialize_public_key(ctx.session_keying_material.key);
    assert(ctx.session_keying_material.public_key.count > 0);
  }
  return ctx.session_keying_material;
}
generate_additional_data :: (record: DTLS_Record) -> [DTLS_RECORD_SIZE]u8 {
  out: [DTLS_RECORD_SIZE]u8;

  writer := bytes_writer_new(array_view(out,0));

  write_bytes(*writer, record.epoch);
  write_bytes(*writer, record.seq_no.first);
  write_bytes(*writer, record.seq_no.second);
  write_bytes(*writer, record.kind);
  write_bytes(*writer, record.version.major);
  write_bytes(*writer, record.version.minor);
  write_bytes(*writer, record.length);

  return out;

}

//returns the bytes that we have deserialized
_deserialize :: (reader: *Bytes_Reader, x: *Any, size_notes_ommitable := false, caller_loc := #caller_location) -> orign: []u8 { 
  if x.type.(*Type_Info).type != .STRUCT unreachable("only supports struct given %\n", x.type);
  x_type := cast(*Type_Info_Struct)x.type; 
  start := reader.cursor;

  for x_type.members {
    notes := it.notes;
    if equal(it.name, "_") continue;

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
      sz := bytes_to_int(read_string_no_copy(reader, read_sz), s64);
      assert(read_sz <= 8);

      read_array: [..]Any;
      read_array.allocator = temp;

      if inner_type.type == .STRUCT {
        bytes_read := 0;
        while bytes_read < sz {
          as_any: Any;
          as_any.type = inner_type;
          as_any.value_pointer = talloc(inner_type_size);

          omit_size := ifx has_note(it.notes, "DefaultSize") true else false;
          start := reader.cursor;
          _deserialize(reader, *as_any, omit_size);
          array_add(*read_array, as_any); 
          end := reader.cursor;
          bytes_read += end - start;
        }
        // malformed packet
        if bytes_read > sz unreachable("oh healll nawww! read % bytes while sz was %\n", bytes_read, sz);
        vla_as_array := array_start_ptr.(*[]u8);
        vla_as_array.count = read_array.count;
        // @leak
        reflection_array: [..]u8;
        for read_array {
          assert(it.value_pointer != null && it.type.type == .STRUCT);
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
        // if array_kind != .FIXED unreachable("only fixed array is supported given % in %.%\n",array_kind, x_type.name, it.name);

        count, data := get_array_count_and_data(x.value_pointer.(*u8) + it.offset_in_bytes, as_array_type_info);
        assert(count >= sz, tprint("array_count % is less than @Size % for %.%\n", count, sz, x_type.name, it.name));
        memcpy(data, view.data, sz);
      }

    } else {
      unreachable("failed to deserialize message %.% has unknown notes %!\n", x_type.name, it.name, notes);
    }
  }
  return array_view(reader.bytes, start, reader.cursor - start);
}

_dtls_value_deserialize :: (reader: *Bytes_Reader, kind: DTLS_Handshake_Kind) -> DTLS_Handshake_Value, []u8 {
  value := DTLS_Handshake_Value.{};
  orig_bytes: []u8;
  if kind == {
    case .HELLO_REQUEST; {
      set(*value, DTLS_Hello_Request.{});
    }
    case .CLIENT_HELLO; {
      serialized: DTLS_Client_Hello;
      orig_bytes = _deserialize(reader, *to_any(*serialized));
      set(*value, serialized);
    }
    case .SERVER_HELLO; {
      serialized: DTLS_Server_Hello;
      orig_bytes = _deserialize(reader, *to_any(*serialized));
      set(*value, serialized);
    }
    case .HELLO_VERIFY_REQUEST; {
      serialized: DTLS_Hello_Verify;
      orig_bytes = _deserialize(reader, *to_any(*serialized));
      set(*value, serialized);
    }
    case .SERVER_HELLO_DONE; {
      serialized: DTLS_Server_Hello_Done;
      orig_bytes = _deserialize(reader, *to_any(*serialized));
      set(*value, serialized);
    }
    case .CERTIFICATE; {
      serialized: DTLS_Certificate_List;
      orig_bytes = _deserialize(reader, *to_any(*serialized));
      set(*value, serialized);
    }
    case .SERVER_KEY_EXCHANGE; { 
      serialized: DTLS_ECDHParams;
      orig_bytes = _deserialize(reader, *to_any(*serialized));
      set(*value, serialized);
    }
    case .CERTIFICATE_REQUEST; {
      // @todo handle this
    }
    case .FINISHED; {
      serialized: DTLS_Message_Finish;
      serialized.verify_data = xx alloc_string(12);
      orig_bytes = _deserialize(reader, *to_any(*serialized));
      set(*value, serialized);
    }
    case; unreachable("% deserialize is not implemented!", kind);
  }
  return value, orig_bytes;
}

dtls_message_deserialize :: (buf: []u8) -> DTLS_Handshake_Message, DTLS_Message_Raw {
  reader := Bytes_Reader.{ bytes = buf };
  record: DTLS_Record;
  hdr: DTLS_Handshake_Header;
  bytes_rec := _deserialize(*reader, *to_any(*record));
  bytes_hdr := _deserialize(*reader, *to_any(*hdr));
  value, bytes_val := _dtls_value_deserialize(*reader, hdr.kind);

  // @todo remove this shit 
  if hdr.kind == .CERTIFICATE_REQUEST { 
    assert(bytes_val.count == 0);
    bytes_val = array_view(reader.bytes, reader.cursor, hdr.length);
    reader.cursor += bytes_val.count;
  }

  msg := DTLS_Handshake_Message.{
    record = record,
    header = hdr,
    value = value,
  };

  entire_msg_bytes := array_view(buf, 0, reader.cursor);

  return msg, .{ reader.cursor, entire_msg_bytes, bytes_rec, bytes_hdr, bytes_val };
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

dtls_message_make :: (ctx: *DTLS_Context, kind: DTLS_Handshake_Kind, msg_len: s64) -> DTLS_Record, DTLS_Handshake_Header {
  record := dtls_handsake_record_default(ctx.seq_no);
  record.epoch = ctx.epoch;
  record.length = cast(u16)(DTLS_HANDSHAKE_HEADER_SIZE + msg_len);
  header := dtls_handshake_header_default(kind, ctx.seq_no.second); // chat is this right?
  header.fragment_length = record.length - DTLS_HANDSHAKE_HEADER_SIZE;
  header.length = record.length - DTLS_HANDSHAKE_HEADER_SIZE;
  return record, header;
}



dtls_message_certificate :: (ctx: *DTLS_Context, cert_list: DTLS_Certificate_List) -> DTLS_Handshake_Message {
  value_size := dtls_message_get_size(DTLS_Certificate_List, cert_list.certs);
  record, header := dtls_message_make(ctx, .CERTIFICATE, value_size);

  value: DTLS_Handshake_Value;
  set(*value, cert_list);

  msg := DTLS_Handshake_Message.{
    record = record,
    header = header,
    value = value,
  };

  return msg;
}
dtls_message_client_hello :: (ctx: *DTLS_Context, session_id: []u8, cookie: []u8, cipher_suites: []DTLS_Cipher_Suite, comp_methods: []DTLS_Compression_Method, exts: []DTLS_Extension) -> DTLS_Handshake_Message {

  // is this session based chat???
  if ctx.ctx_random.gmt_unix_time == 0 ctx.ctx_random = .{ _get_gm_time(), random_n_bytes(28) };
  value_size := dtls_message_get_size(DTLS_Client_Hello, session_id, cookie, cipher_suites, comp_methods, exts);
  record, header := dtls_message_make(ctx, .CLIENT_HELLO, value_size);


  value: DTLS_Handshake_Value;
  hello_verify := DTLS_Client_Hello.{
    client_version = DTLS_VERSION_1_2,
    random = ctx.ctx_random,
    cookie = cookie,
    cipher_suites = cipher_suites,
    compression_methods = comp_methods,
    extensions = exts,
  };
  set(*value, hello_verify);

  msg := DTLS_Handshake_Message.{
    record = record,
    header = header,
    value = value,
  };
  return msg;

}

dtls_message_prep_client_hello :: (ctx: *DTLS_Context, session_id: []u8, cookie: []u8, extra_ext: []DTLS_Extension = .[]) -> DTLS_Handshake_Message {
  return dtls_message_client_hello(ctx, session_id, cookie, DTLS_SUPPORTED_CIPHER_SUITES, DTLS_SUPPORTED_COMPRESSION_METHODS, extra_ext);
}

dtls_message_client_key_exch :: (ctx: *DTLS_Context) -> DTLS_Handshake_Message {
  eph_key := dtls_get_session_keying_material(ctx);
  epkey := eph_key.public_key;

  value_size := dtls_message_get_size(DTLS_Client_Key_Exchange, epkey);
  record, header := dtls_message_make(ctx, .CLIENT_KEY_EXCHANGE, value_size);
  
  value: DTLS_Handshake_Value;
  key_exch := DTLS_Client_Key_Exchange.{ epkey };
  set(*value, key_exch);

  msg := DTLS_Handshake_Message.{
    record = record,
    header = header,
    value = value,
  };
  return msg;
}


// @todo signature is redundant
dtls_message_certificate_verify :: (ctx: *DTLS_Context, signature: []u8) -> DTLS_Handshake_Message {
  value_size := dtls_message_get_size(DTLS_Certificate_Verify, signature);
  record, header := dtls_message_make(ctx, .CERTIFICATE_VERIFY, value_size);

  value: DTLS_Handshake_Value;
  cert_verify := DTLS_Certificate_Verify.{
    sign_algo =  SIGNATURE_ALGORITHM_ECDSA_SECP256R1_SHA256,
    signature = signature,
  };
  set(*value, cert_verify);

  msg := DTLS_Handshake_Message.{
    record = record,
    header = header,
    value = value,
  };
  return msg;
}


dtls_message_change_cipher_spec :: (ctx: *DTLS_Context) -> DTLS_Handshake_Message {
  record := DTLS_Record.{
    kind = .CHANGE_CIPHER_SPEC,
    version = DTLS_VERSION_1_2,
    epoch = 0,
    seq_no = ctx.seq_no,
    length = 1,
  };

  value: DTLS_Handshake_Value;
  cipher_specs := DTLS_Change_Cipher_Spec.{};

  set(*value, cipher_specs);

  return .{
    record = record,
    header = dtls_handshake_header_default(.HELLO_REQUEST, 0), // sm bs handshake
    value = value,
  };
}

A_SHA256 :: (secret: string, seed: string, iter: s64) -> string {
  // A() is defined as:

  // A(0) = seed
  // A(i) = HMAC_hash(secret, A(i-1))
  if iter == 0 return seed;
  return hmac_sha256(secret, A_SHA256(secret, seed, iter - 1));

}

P_SHA256 :: (secret: string, seed: string, output_length: s64) -> string {

  // HMAC_hash(secret, A(1) + seed) +
  // HMAC_hash(secret, A(2) + seed) +
  // HMAC_hash(secret, A(3) + seed) + ...

  final := "";
  n_iter := cast(s64)ceil(output_length.(float) / 32.);

  for 1..n_iter {
    final = join(final, hmac_sha256(secret, join(A_SHA256(secret, seed, it), seed)));
  }

  return slice(final, 0, output_length);
}
Random_Struct :: struct {
  client_random: DTLS_Random; @InnerSize
  server_random: DTLS_Random; @InnerSize
}
dtls_get_key_block :: (using dtls_ctx: *DTLS_Context) ->  DTLS_Key_Block {
  if key_block.entire.count == 0 {
    assert(session_keying_material.master_key.count != 0);
    return dtls_generate_key_block(dtls_ctx, xx session_keying_material.master_key, ctx_random, remote_last_random);
  }
  return key_block;
}




// The exporter label for this usage is "EXTRACTOR-dtls_srtp".  (The
// "EXTRACTOR" prefix is for historical compatibility.)
dtls_exporter :: (dtls_ctx: *DTLS_Context, label: string, n_bytes: s64) -> []u8 {
  // @todo generates wrong shit if we are server
  client_random := dtls_ctx.ctx_random;
  server_random := dtls_ctx.remote_last_random;
  random := Random_Struct.{ client_random, server_random };
  randoms_as_bytes := serialize(random,, allocator = temp);
  master_key := dtls_ctx.session_keying_material.master_key;

  return xx PRF(xx master_key, label, xx randoms_as_bytes, n_bytes);
}

dtls_generate_key_block :: (dtls_ctx: *DTLS_Context, master_secret: string, client_random: DTLS_Random, server_random: DTLS_Random) -> DTLS_Key_Block {
  random := Random_Struct.{ server_random, client_random };
  randoms_as_bytes := serialize(random,, allocator = temp);
  key_block_as_bytes: []u8 = xx PRF(master_secret, "key expansion", xx randoms_as_bytes, 40);

  key_block := DTLS_Key_Block.{
    client_write_key = xx array_view(key_block_as_bytes, 0, 16),
    server_write_key = xx array_view(key_block_as_bytes, 16, 16),
    client_write_IV  = xx array_view(key_block_as_bytes, 32,  4),
    server_write_IV  = xx array_view(key_block_as_bytes, 36,  4),
    entire = key_block_as_bytes,
  };
  dtls_ctx.key_block = key_block;

  return key_block;
}

PRF :: (secret: string, label: string, seed: string, output_length: s64) -> string {
  // @todo based one the value from cipher suites
  return copy_string(P_SHA256(secret, join(label, seed,, allocator = temp), output_length,, allocator = temp));
}


generate_master_key :: (client_random: DTLS_Random, server_random: DTLS_Random, pre_master_secret: string) -> []u8 {
  random := Random_Struct.{ client_random, server_random };
  randoms_as_bytes := serialize(random,, allocator = temp);

  // https://datatracker.ietf.org/doc/html/rfc5246#section-8.1
  master_key_bytes: []u8 = xx PRF(pre_master_secret, "master secret", xx randoms_as_bytes, 48);
  return master_key_bytes;
}

dtls_get_master_key :: (dtls_ctx: *DTLS_Context) -> []u8 {
  assert(dtls_ctx.session_keying_material.master_key.count > 0,
    "master key is not generated! call dtls_generate_master_key() to generate it."
  );
  return dtls_ctx.session_keying_material.master_key;
}

dtls_cipher_text_finish :: (ctx: *DTLS_Context, aead: DTLS_AEAD_Cipher) -> DTLS_Cipher_Text {

  finish_label := dtls_get_finish_label(ctx);

  value_size := dtls_message_get_size(DTLS_AEAD_Cipher, aead.content);
  record, header := dtls_message_make(ctx, .FINISHED, value_size);
  record.length -= DTLS_HANDSHAKE_HEADER_SIZE;

  return .{
    record = record,
    aead = aead,
  };
}

dtls_cipher_text_serialize :: (msg: DTLS_Cipher_Text) -> []u8 {
  total_length := DTLS_RECORD_SIZE + msg.record.length;
  serialized: []u8 = xx alloc_string(total_length);
  writer := Bytes_Writer.{
    cursor = 0,
    bytes = serialized,
    should_swap = true,
  };
  record := _serialize(*writer, msg.record);
  aead := _serialize(*writer, msg.aead);

  return serialized;
}

dtls_message_finish :: (ctx: *DTLS_Context, verify_data: []u8) -> DTLS_Handshake_Message {
  finish_label := dtls_get_finish_label(ctx);

  value_size := dtls_message_get_size(DTLS_Message_Finish);
  record, header := dtls_message_make(ctx, .FINISHED, value_size);

  value: DTLS_Handshake_Value;
  finish := DTLS_Message_Finish.{ verify_data };
  set(*value, finish);

  msg := DTLS_Handshake_Message.{
    record = record,
    header = header,
    value = value,
  };
  return msg;

}

dtls_message_hello_verify :: (ctx: *DTLS_Context, client_hello: DTLS_Handshake_Message, cookie: []u8) -> DTLS_Handshake_Message {
  value_size := dtls_message_get_size(DTLS_Hello_Verify, cookie);
  record, header := dtls_message_make(ctx, .HELLO_VERIFY_REQUEST, value_size);
  record.seq_no = client_hello.record.seq_no; // @need_context @priority should we also change the seq_no 
                                              //of header?

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


dtls_message_server_hello :: (ctx: *DTLS_Context, client_hello: DTLS_Handshake_Message, exts: []DTLS_Extension) -> DTLS_Handshake_Message {

  value_size := dtls_message_get_size(DTLS_Server_Hello, cast([]u8)"", exts);
  record, header := dtls_message_make(ctx, .SERVER_HELLO, value_size);

  client_hello_value := isa(client_hello.value, DTLS_Client_Hello); assert(client_hello_value != null);
  ok, suite := _get_supported_cipher_suite(client_hello_value);
  if !ok {
    log_err("we only support % cipher\n", TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    log_err("given ciphers:\n%\n", client_hello_value.cipher_suites);
    assert(false, "unreachable");
  }

  value: DTLS_Handshake_Value;
  server_hello := DTLS_Server_Hello.{
    server_version = DTLS_VERSION_1_0,
    random = ctx.ctx_random,
    cipher_suite = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    compression_method = .NULL,
    extensions = exts,
  };
  set(*value, server_hello);

  msg := DTLS_Handshake_Message.{
    record = record,
    header = header,
    value = value,
  };
  return msg;
}

dtls_message_server_hello_done :: (ctx: *DTLS_Context) -> DTLS_Handshake_Message {
  record, header := dtls_message_make(ctx, .SERVER_HELLO_DONE, 0);

  value: DTLS_Handshake_Value;
  server_hello_done := DTLS_Server_Hello_Done.{};
  set(*value, server_hello_done);

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
// @todo well we force edcsa anyways so ts is not used right now
_extension_signature_algorithms :: () -> DTLS_Extension {
  algo := DTLS_Signature_Hash_Algorithms.{ .[SIGNATURE_ALGORITHM_ED25519] };
  bytes := alloc_string(4);
  writer := Bytes_Writer.{
    bytes = xx bytes,
    should_swap = true,
  };
  _serialize(*writer, to_any(*algo));
  return DTLS_Extension.{
    kind = .SIGNATURE_ALGORITHMS,
    data = xx bytes, 
  };
}

dtls_message_get_cookie :: (msg: DTLS_Handshake_Message) -> bool, []u8 {
  if msg.header.kind == {
    case .CLIENT_HELLO; {
      value := isa(*msg.value, DTLS_Client_Hello); assert(value != null);
      return value.cookie.count != 0, value.cookie;
    }
    case .HELLO_VERIFY_REQUEST; {
      value := isa(*msg.value, DTLS_Hello_Verify); assert(value != null);
      return value.cookie.count != 0, value.cookie;
    }
    case; assert(false, "unimplemented!");
  }
  return false, .[];
}

dtls_cipher_text_send :: (ctx: *DTLS_Context, msg: DTLS_Cipher_Text, conn: Socket_Connection) {
  log_debug("sending cipher text message % %\n",msg.record.kind, msg.record.seq_no.second);
  ser := dtls_cipher_text_serialize(*msg);
  sz := conn_udp_write(conn, xx ser);
  assert(sz == ser.count , tprint("udp write returned %: %\n", sz, strerror(errno())));
  ctx.seq_no += 1;
}
// @todo conn and to should be the part of context
dtls_message_send :: (ctx: *DTLS_Context, msg: DTLS_Handshake_Message, conn: Socket_Connection) {
  log_debug("sending message % % %\n",msg.record.kind, msg.header.kind, msg.record.seq_no.second);
  if msg.record.kind == {
    case .HANDSHAKE; {
      ser, raw := dtls_message_serialize(*msg);
      sz := conn_udp_write(conn, xx ser);
      assert(sz == ser.count , tprint("udp write returned %: %\n", sz, strerror(errno())));
      if ctx.flight == 4 array_add(*ctx.flight4_messages, raw);

      ctx.seq_no += 1;
    }
    case .CHANGE_CIPHER_SPEC; {
      total_length := DTLS_RECORD_SIZE + msg.record.length;
      serialized: []u8 = xx alloc_string(total_length);
      writer := Bytes_Writer.{
        bytes = serialized,
        should_swap = true,
      };
      record := _serialize(*writer, msg.record);
      as_cipher_spec := isa(msg.value, DTLS_Change_Cipher_Spec);
      assert(as_cipher_spec != null);
      header := _serialize(*writer, as_cipher_spec.*);
      sz := conn_udp_write(conn, xx serialized);
      assert(sz == serialized.count , tprint("udp write returned %: %\n", sz, strerror(errno())));
      // we do not append the seq no because this is not really a dtls message
    }
  }
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

dtls_ecdsa_verify :: (buf: []u8, key: Crypto_Key, signature: []u8) -> bool {
  ctx := EVP_MD_CTX_new(); assert(ctx != null);
  assert(ctx != null);
  defer EVP_MD_CTX_free(ctx);
  assert(EVP_DigestVerifyInit(ctx, null, EVP_sha256(), null, key.key) == 1);
  assert(EVP_DigestVerifyUpdate(ctx, buf.data, buf.count) == 1);

  result := EVP_DigestVerifyFinal(ctx, signature.data, cast(s64)signature.count);
  return result == 1;
}
// @todo @perf this is ass
dtls_certificate_get_pubkey :: (using dtls_cert: DTLS_Certificate) -> Crypto_Key {
  as_x509 := d2i_X509(null, *cert.data, xx cert.count);
  assert(as_x509 != null);
  pk := Crypto_Key.{ key = X509_get_pubkey(as_x509) };
  assert(pk.key != null);
  X509_free(as_x509);
  return pk;
}
// @leak
serialize :: (x: $T) -> []u8 {
  sz := dtls_message_get_size(x);
  buf: []u8 = xx alloc_string(sz);
  writer := Bytes_Writer.{
    bytes = buf,
    should_swap = true,
  };
  _serialize(*writer, x);
  return buf;
}
_serialize :: (writer: *Bytes_Writer, x: Any, size_notes_ommitable := false, caller_loc := #caller_location) -> []u8 {
  assert(x.type.type == .STRUCT, tprint("wanted struct got %\n", x.type.type));
  x_type := cast(*Type_Info_Struct)x.type;
  start := writer.cursor;
  
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
      assert(sz <= 8);
      data_ptr := x.value_pointer.(*u8) + it.offset_in_bytes;
      for 0 .. sz-1 write_bytes(writer,  (data_ptr +  sz - 1 - it).(*u8).* & 0xff);

    } else if has_note(notes, "Vla") {
      if it.type.type != .ARRAY {
        unreachable("Vla needs to be array provided % for %.%\n", it.type.type, x_type.name, it.name);
      }
      vla_array_info := it.type.(*Type_Info_Array);
      vla_array_count, vla_array_data := get_array_count_and_data(x.value_pointer.(*u8) + it.offset_in_bytes, vla_array_info);

      sz := string_to_int(notes[1]);
      inner_type := vla_array_info.element_type;
      inner_type_size := inner_type.runtime_size;
      assert(inner_type_size != -1);
      total_size := 0;

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
          da_size := dtls_message_get_size_runtime(inner_type.(*Type_Info_Struct), arg_array);
          total_size += da_size;
          array_reset_keeping_memory(*arg_array);
        }
        assert(total_size != 0);
      } else {
        total_size = vla_array_count * inner_type_size;
      }

      assert(sz <= 8);
      data_ptr := int_to_bytes(8, total_size).data;

      for 0 .. sz-1 write_bytes(writer,  (data_ptr + 8 - sz + it).(*u8).*);
      if inner_type.type == .STRUCT {
        omit_size := ifx has_note(it.notes, "DefaultSize") true else false;
        for 0..vla_array_count-1 {
          as_any: Any;
          as_any.type = inner_type;
          as_any.value_pointer = vla_array_data + it * inner_type.runtime_size;
          _serialize(writer, as_any, omit_size);
        }
      } else {
        as_byte_slice: []u8;
        as_byte_slice.data = vla_array_data;
        as_byte_slice.count = vla_array_count * inner_type_size;
        write_string(writer, cast(string) as_byte_slice);
      }
    } else if has_note(notes, "Array") {
      data_ptr := x.value_pointer.(*u8) + it.offset_in_bytes;
      if it.type.type == .INTEGER {
        for 0 .. sz-1 write_bytes(writer,  (data_ptr +  sz - 1 - it).(*u8).* & 0xff);

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
  return array_view(writer.bytes, start, writer.cursor - start); 
}

dtls_message_raw_clone :: (raw: DTLS_Message_Raw) -> DTLS_Message_Raw {
  new: []u8 = xx copy_string(raw.entire);

  new_message := DTLS_Message_Raw.{
    size = raw.size,
    entire = new,
    record = array_view(new, 0, raw.record.count),
    header = array_view(new, raw.record.count, raw.payload.count),
    payload = array_view(new, raw.payload.count),
  };
  return new_message;
}
dtls_message_serialize :: (msg: *DTLS_Handshake_Message) -> (all: []u8, raw: DTLS_Message_Raw) {
  total_length := DTLS_RECORD_SIZE + msg.record.length;
  serialized: []u8 = xx alloc_string(total_length);
  writer := Bytes_Writer.{
    cursor = 0,
    bytes = serialized,
    should_swap = true,
  };
  record := _serialize(*writer, msg.record);
  header := _serialize(*writer, msg.header);

  value_as_any: Any;
  value_as_any.type = msg.value.tag.(*Type_Info);
  value_as_any.value_pointer = msg.value.bytes.data;
  payload := _serialize(*writer, value_as_any);

  entire_msg_view := array_view(writer.bytes, 0, writer.cursor);
  return writer.bytes, .{ writer.cursor, entire_msg_view, record, header, payload };
}

has_note :: (haysack: []string, needle: string) -> bool {
  for haysack if equal(it, needle) return true;
  return false;
}

_message_size_calc :: (struct_info: *Type_Info_Struct, caller_loc: Source_Code_Location, zero_vla := false) -> s64, s64 {
  sz := 0;
  n_vlas := 0;
  for struct_info.members {
    if equal(it.name, "_") continue;
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
          "error getting size for %.%! We do not implement recursive calcuation of sizes! please add a field _:void; @Size in struct %",
          struct_info.name, it.name, as_struct.name);
      }
      size := string_to_int(size_field.notes[1]); assert(size > 0);
      sz += size;
    } else if has_note(it.notes, "Vla") {
      as_int := string_to_int(it.notes[1]);
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
dtls_message_get_size :: (x: $T) -> s64 {
  arg_array: [..]Any;
  x_type := type_of(x).(*Type_Info_Struct);
  for x_type.members {
    if !has_note(it.notes, "Vla") continue;
    as_any: Any;
    as_any.type = it.type;
    as_any.value_pointer = (*x).(*u8) + it.offset_in_bytes;

    array_add(*arg_array, as_any);
  }
  return dtls_message_get_size_runtime(x_type, arg_array);
}

dtls_message_get_size_runtime :: (msg_type: *Type_Info_Struct, values: []Any, $loc := #caller_location) -> s64 {
  sz, n_vlas := _message_size_calc(msg_type, loc);

  for values {
    assert(it.type.type == .ARRAY, tprint("VLAs are array bruh... given % for %\n", it.type.type, msg_type.name));
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
    assert(any_value.type.type == .ARRAY, tprint("VLAs are array bruh... given % for %\n", any_value.type.type, msg_type.(*Type_Info_Struct).name));
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
        case .ENUM; {
          as_enum := element_type.(*Type_Info_Enum);
          if as_enum.internal_type.type != .INTEGER {
            unreachable("wanted type INTEGER got %\n", as_enum.internal_type.type);
          }
          count := ifx as_array.array_type == .FIXED as_array.array_count
          else any_value.value_pointer.(*[]u8).*.count;
          elem_size := element_type.runtime_size; assert(elem_size != -1);
          sz += count * elem_size;
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

dtls_certificate_create_fingerprint :: (cert: DTLS_Certificate) -> string {
  cert_hashed := sha256(cert.cert);
  builder := String_Builder.{allocator = temp};
  for cert_hashed {
    if (it >> 4) & 0xf == 0 print_to_builder(*builder, "0%", formatHex(it));
    else print_to_builder(*builder, "%", formatHex(it));
    if it_index != cert_hashed.count -1  {
      print_to_builder(*builder, ":");
    }
  }
  str := builder_to_string(*builder);
  to_upper_in_place(str);
  return str;
}



#scope_file
#import "utils";
#import "OpenSSL";
#import "Tagged_Union";
#import "Basic";
#import "Random";
#import "POSIX";
#import "Compiler";
#import "Log";
#import "String";
#import "Reflection";
#import "Net";
#import "File";
#import "Math";
