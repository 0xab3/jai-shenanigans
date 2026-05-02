MAGIC_COOKIE :: cast(u32)0x2112A442;

// @remove ufrag and upwd should come from ice candidates
Stun_Message_Kind_Sane :: enum u16 {
  REQUEST              ::  0b00;
  INDICATION           ::  0b01;
  SUCCESS_RESPONSE     ::  0b10;
  ERROR_RESPONSE       ::  0b11;
};

STUN_HEADER_TYPE_BIT_C0 :: 1 << 4;
STUN_HEADER_TYPE_BIT_C1 :: 1 << 8;

Stun_Message_Kind :: enum_flags u16 {
  REQUEST                       ::  0x0;
  INDICATION                    ::  STUN_HEADER_TYPE_BIT_C0;
  SUCCESS_RESPONSE              ::  STUN_HEADER_TYPE_BIT_C1;
  ERROR_RESPONSE                ::  STUN_HEADER_TYPE_BIT_C0 | STUN_HEADER_TYPE_BIT_C1;
  BIND                          ::  0x1;

};

Stun_Transaction_Id :: Pair(u64, u32);

operator == :: (x: Stun_Transaction_Id, y: Stun_Transaction_Id) -> bool {
  return (x.first == y.first) && (x.second == y.second);
}

transaction_id_eq :: (x: Stun_Transaction_Id, y: Stun_Transaction_Id) -> bool {
  return x == y;
}
transaction_id_hash :: (x: Stun_Transaction_Id) -> u32 {
  as_str: string;
  as_str.data = cast(*u8)*x.first;
  as_str.count = size_of(Stun_Transaction_Id);
  return get_hash(as_str);
}

Stun_Header :: struct {
  kind: u16;
  length:  u16;
  magic_cookie: u32;
  transaction_id: Stun_Transaction_Id;
} #no_padding;

#assert size_of(Stun_Header) == 20;

Stun_Attribute_Kind :: enum u16 {
   // from RFC 8489
   MAPPED_ADDRESS                     :: 0x0001;
   USERNAME                           :: 0x0006;
   MESSAGE_INTEGRITY                  :: 0x0008;
   ERROR_CODE                         :: 0x0009;
   UNKNOWN_ATTRIBUTES                 :: 0x000A;
   REALM                              :: 0x0014;
   NONCE                              :: 0x0015;
   XOR_MAPPED_ADDRESS                 :: 0x0020;

   // from RFC 5245
   PRIORITY                           :: 0x0024; // PRIORITY // @note same as candidate priority
   USE_CANDIDATE                      :: 0x0025; // USE-CANDIDATE
   ICE_CONTROLLED                     :: 0x8029; // ICE-CONTROLLED
   ICE_CONTROLLING                    :: 0x802A; // ICE-CONTROLLING

   // pion uses this
   // optional range 0x8000-0xFFFF
   FINGERPRINT                     :: 0x8028;
};

Stun_Attribute_Header :: struct {
  kind: Stun_Attribute_Kind;
  length: u16;
};

Stun_Attribute_None :: void;

Stun_Attribute_Mapped :: struct {
  using #as addr_info: Socket_Address;
};

Stun_Attribute_Username :: struct {
  remote, local: string;
};

Stun_Attribute_Priority :: struct {
  priority: u32;
};

Stun_Attribute_Integrity :: struct {
  key: string;
  hmac: string;
};

Stun_Attribute_IceControl :: struct {tie_breaker: u64;};

Stun_Attribute_Fingerprint :: struct {
  crc: s32;
};

Stun_Attribute_Value :: Tagged_Union(
  Stun_Attribute_None,
  Stun_Attribute_Mapped,
  Stun_Attribute_Username,
  Stun_Attribute_Priority,
  Stun_Attribute_Integrity,
  Stun_Attribute_IceControl,
  Stun_Attribute_Fingerprint,
);

Stun_Attribute :: struct {
  header: Stun_Attribute_Header;
  value: Stun_Attribute_Value;
};

Stun_Message :: struct {
  using #as header: Stun_Header;
  attributes: [..]Stun_Attribute;
};

length_align :: (length: $T, alignment := 4) -> T #expand {
  a :: alignment;
  return ifx length % a != 0  length + a - (length % a) else length;
}

stun_header_kind_sane :: (header: *Stun_Header) -> Stun_Message_Kind_Sane {
  kind :u32 = header.kind;
  mask :u32 = xx (STUN_HEADER_TYPE_BIT_C0 | STUN_HEADER_TYPE_BIT_C1);
  as_sane : u32 = 0;
  #asm {
     pext as_sane, kind, mask;
  }
  _sane := as_sane;
  return xx _sane;
}

// @todo use Bytes_Reader here
stun_message_deserialize :: (res: []u8) -> Stun_Message {
  assert(res.count >= 20, tprint("stun message should atleast be 20 bytes, given % bytes!", res.count));
  parsed_message: Stun_Message;
  res_header := cast(*Stun_Header)res.data;

  kind := stun_header_kind_sane(res_header);

  assert(BYTE_SWAP(res_header.kind) & xx Stun_Message_Kind.BIND != 0);

  if kind == {
    case .REQUEST;{}
    case .INDICATION; assert(false, "INDICATION is not implemented!");
    case .SUCCESS_RESPONSE; {};
    case .ERROR_RESPONSE; assert(false, "ERROR_RESPONSE is not implemented!");
  }
  // TODO(shahzad): we do not parse method and assume that the server will only send the bind one

  parsed_message.header = .{
    kind = xx BYTE_SWAP(res_header.kind),
    length = BYTE_SWAP(res_header.length),
    magic_cookie = BYTE_SWAP(res_header.magic_cookie),
    transaction_id.first = res_header.transaction_id.first,
    transaction_id.second = res_header.transaction_id.second, // idk why but we don't have to do swap
  };

  str := to_string(parsed_message.header);
  assert(parsed_message.header.length & 0b11 == 0); // the value is padded to be multiple of 4 bytes

  // skip the payload first
  attribute_view := array_view(res, size_of(Stun_Header), res.count);

  bytes_consumed_while_parsing_attrs := 0;
  while bytes_consumed_while_parsing_attrs < parsed_message.header.length && attribute_view.count > 0 {
    attr : Stun_Attribute;
    attr_header: Stun_Attribute_Header;
    attr_value: Stun_Attribute_Value;

    attr_header = .{
      kind = xx BYTE_SWAP(attribute_view.data.(*u16).*),
      length = BYTE_SWAP((attribute_view.data + 2).(*u16).*),
    };
    bytes_consumed_while_parsing_attrs += 4;
    attr.header = attr_header;

    if attr_header.kind == {
      case .XOR_MAPPED_ADDRESS; {
          attribute_value_view := array_view(attribute_view, size_of(Stun_Attribute_Header), res.count);
          value := Stun_Attribute_Mapped.{
            port = xx BYTE_SWAP(BYTE_SWAP((attribute_value_view.data + 2).(*u16).*) ^ cast(u16) (MAGIC_COOKIE >> 16)),
            addr = .{
            ip_addr = BYTE_SWAP(BYTE_SWAP((attribute_value_view.data + 4).(*u32).*) ^ MAGIC_COOKIE),
            family =  xx (attribute_value_view.data + 1).(*u8).*},
          };

          assert(value.addr.family == .IPV4, "we do not support IPV6 at all!"); // right now atleast

          set(*attr_value, value);
      }
      case .USERNAME; {
        attribute_value_view := array_view(attribute_view, size_of(Stun_Attribute_Header), res.count);
        username_pair := cast(string)attribute_value_view;
        username_pair.count = attr_header.length;
        ok, local, remote := split_from_left(username_pair, ":");
        assert(ok);
        value := Stun_Attribute_Username.{
          local = local,
          remote = remote,
        };
        set(*attr_value, value);
      }
      case .MESSAGE_INTEGRITY; {
        attribute_value_view := array_view(attribute_view, size_of(Stun_Attribute_Header), res.count);
        hmac := cast(string)attribute_value_view;
        hmac.count = 20;
        value := Stun_Attribute_Integrity.{
           key = "",
           hmac = hmac,
        };
        set(*attr_value, value);
      }
      case .PRIORITY; {
        attribute_value_view := array_view(attribute_view, size_of(Stun_Attribute_Header), res.count);
        priority := BYTE_SWAP((attribute_value_view.data).(*u32).*);
        value := Stun_Attribute_Priority.{
           priority = priority,
        };
        set(*attr_value, value);
      }
      case .ICE_CONTROLLING; #through;
      case .ICE_CONTROLLED; {
        attribute_value_view := array_view(attribute_view, size_of(Stun_Attribute_Header), res.count);
        tie_breaker := BYTE_SWAP((attribute_value_view.data).(*u64).*);
        value := Stun_Attribute_IceControl.{
           tie_breaker = tie_breaker,
        };
        set(*attr_value, value);
      }
      case; {
        if attr_header.kind < 0x8000 {
          // we don't care about them atp
          // print("required attr_type % is unimplimented!\n", formatInt(cast(u16)attr_header.type, 16));
        }
        // print("optional attr_type % is unimplimented!\n", formatInt(cast(u16)attr_header.type, 16));
      }
    }
    bytes_consumed_while_parsing_attrs += length_align(attr_header.length);
    attr.value = attr_value;
    array_add(*parsed_message.attributes, attr);

    new_length := length_align(attr_header.length);
    attribute_view = array_view(attribute_view, size_of(Stun_Attribute_Header) + new_length, attribute_view.count);
  }
  assert(bytes_consumed_while_parsing_attrs <= parsed_message.header.length);
  return parsed_message;
}

stun_message_serialize :: (msg: *Stun_Message) -> string {
  total_length := msg.header.length + size_of(Stun_Header);
  deserialized := alloc_string(total_length);
  writer:= Bytes_Writer.{
    cursor = 0,
    bytes =  xx deserialized,
  };

  write_bytes(*writer, BYTE_SWAP(msg.kind));
  header_length_idx := writer.cursor;
  write_bytes(*writer, BYTE_SWAP(msg.header.length));
  write_bytes(*writer, BYTE_SWAP(msg.header.magic_cookie));
  write_bytes(*writer, msg.header.transaction_id.first);
  write_bytes(*writer, msg.header.transaction_id.second);

  for msg.attributes {
    header := it.header;
    value := it.value;
    if value.tag != Stun_Attribute_Integrity {
      write_bytes(*writer, BYTE_SWAP(cast(u16)header.kind));
      write_bytes(*writer, BYTE_SWAP(header.length));
    }

    if value.tag == {
      case Stun_Attribute_Mapped;
        as_mapped_attr := isa(value, Stun_Attribute_Mapped); assert(as_mapped_attr != null);
        if it.header.kind == .XOR_MAPPED_ADDRESS {

          write_bytes(*writer, BYTE_SWAP(cast(u16)as_mapped_attr.addr.family));
          // convert network to host then back to network
          write_bytes(*writer, BYTE_SWAP(BYTE_SWAP(as_mapped_attr.port) ^ cast(u16)(MAGIC_COOKIE >> 16)));
          write_bytes(*writer, BYTE_SWAP(BYTE_SWAP(as_mapped_attr.addr.ip_addr) ^ MAGIC_COOKIE));
        }else {
          write_bytes(*writer, BYTE_SWAP(cast(u16)as_mapped_attr.addr.family));
          // already in network order for some reason
          write_bytes(*writer, cast(u16)as_mapped_attr.port);
          write_bytes(*writer, cast(u32)as_mapped_attr.addr.ip_addr);
        }
      case Stun_Attribute_Username;
        as_username_attr := isa(value, Stun_Attribute_Username); assert(as_username_attr != null);
        write_string(*writer, as_username_attr.remote);
        write_string(*writer, ":");
        write_string(*writer, as_username_attr.local);
        remaining := length_align(it.header.length) - it.header.length;
        for 0..remaining-1 write_bytes(*writer, cast(u8)0);
      case Stun_Attribute_Priority;
        as_priority_attr := isa(value, Stun_Attribute_Priority); assert(as_priority_attr != null);
        write_bytes(*writer, BYTE_SWAP(cast(u32)as_priority_attr.priority));
      case Stun_Attribute_Integrity;
        as_integrity_attr := isa(value, Stun_Attribute_Integrity); assert(as_integrity_attr != null);
        // @note if the below assertion fails it means that the message does not have 
        // a key or a hmac, one of the confounder of this is not having any media stream
        // as the key used in integrity attr is ice_pwd, so no media stream no ice_pwd
        // and no hmac (cause hmac is only set when we deserialize this shit)
        assert(as_integrity_attr.hmac.count != 0 || as_integrity_attr.key.count != 0); // only here for distinction the below assertion takes care of this too but yk
        assert((as_integrity_attr.hmac.count == 0) ^ (as_integrity_attr.key.count == 0),
          "we can either have a hmac or a key when deserializing, because we are computing the hmac here, the pre computed hmac creates confusion"
        );
        hmac: string;
        if as_integrity_attr.hmac.count != 0 {
          hmac = as_integrity_attr.hmac;
        } else {
          prev_length := (writer.bytes.data + header_length_idx).(*u16).*;
          mark := writer.cursor;
          writer.cursor = header_length_idx;
          // mark - size_of(Stun_Header) + size_of(hmac) + 4;
          // mark is the current cursor so it is the entire length we have to subtract the Stun_Header
          // length from it as the Stun_Header.length does not contain it's own length after that
          // we have to add the length of the integrity attribute which is size_of(Stun_Attribute_Header) 4,
          // size_of(hmac) 20
          write_bytes(*writer, BYTE_SWAP(cast(u16)mark + 4));
          hmac = hmac_sha1(as_integrity_attr.key, slice(deserialized,0, mark));

          (writer.bytes.data + header_length_idx).(*u16).* = prev_length;

          writer.cursor = mark;
        }
        write_bytes(*writer, BYTE_SWAP(Stun_Attribute_Kind.MESSAGE_INTEGRITY));
        write_bytes(*writer, BYTE_SWAP(cast(u16)20));
        write_string(*writer, hmac);
      case Stun_Attribute_IceControl;
        as_control := isa(value, Stun_Attribute_IceControl); assert(as_control != null);
        tie_breaker := as_control.tie_breaker;
        write_bytes(*writer, BYTE_SWAP(tie_breaker));
      case Stun_Attribute_Fingerprint; {
        as_fingerprint := isa(value, Stun_Attribute_Fingerprint); assert(as_fingerprint != null);
        fingerprint := 0x5354554e ^ crc32(array_view(writer.bytes, 0, writer.cursor - 4));
        write_bytes(*writer, BYTE_SWAP(fingerprint));
      }
    }
  }
  return deserialized;
}
// we can make all of this shit comptime i think
CRC32_POLY :: 0xEDB88320;
crc32_table: [256]u32;
table_init := false;

init_crc32_table :: () {
  for i: 0..255 {
    crc := cast(u32) i;
    for j: 0..7 {
      if (crc & 1) != 0 {
        crc = (crc >> 1) ^ CRC32_POLY;
      } else {
        crc = crc >> 1;
      }
    }
    crc32_table[i] = crc;
  }
  table_init = true;
}

crc32 :: (data: []u8) -> u32 {
  if !table_init init_crc32_table();
  crc: u32 = 0xFFFFFFFF;

  for data {
    index := (crc ^ it) & 0xFF;
    crc = (crc >> 8) ^ crc32_table[index];
  }

  return ~crc;
}


stun_message_try_get_attribute :: (msg: Stun_Message, $T: Type) -> (bool, T) {
  undef: T = ---;
  for msg.attributes {
    value := isa(it.value, T);
    if value != null return true, value.(*T).*;
  }
  return false, undef;
}

stun_header_default :: (kind: Stun_Message_Kind, length: u16 = 0) -> Stun_Header {
  hi, lo := _new_transaction_id();

  return Stun_Header.{
    kind = xx kind,
    length = length,
    magic_cookie = MAGIC_COOKIE,
    transaction_id = .{lo, hi},
  };
}

stun_message_add_attribute :: (msg: *Stun_Message, attributes: ..Stun_Attribute) {
  total_attrib_length: u16 = 0;
  for attributes total_attrib_length += length_align(it.header.length) + size_of(Stun_Attribute_Header);
  array_add(*msg.attributes, ..attributes);
  msg.length += total_attrib_length;
}
stun_message_prepare :: (kind: Stun_Message_Kind, attributes: ..Stun_Attribute) -> Stun_Message {
  total_length: u16 = 0;
  for attributes total_length += length_align(it.header.length) + size_of(Stun_Attribute_Header);

  msg := Stun_Message.{
    header = stun_header_default(kind, total_length),
  };
  array_add(*msg.attributes, ..attributes);
  return msg;
}

stun_message_send :: (msg: *Stun_Message, conn: Socket_Connection) -> s64 {
  deser := stun_message_serialize(msg);
  return conn_udp_write(conn, xx deser);
}

stun_message_prepare_binding_response :: (sock_info: Socket_Address, pwd: string, t_id: Stun_Transaction_Id) -> Stun_Message #expand {
  reply := stun_message_prepare(
    .BIND |.SUCCESS_RESPONSE,
    stun_attribute_xor_mapped(sock_info),
    stun_attribute_integrity(pwd),
  );
  reply.header.transaction_id = t_id;
  return reply;
}

stun_send_binding_request :: (to: *Socket_Connection) -> bool {
  assert(false, "unimplemented!");
  addr := server.addrs[0];
  sock_fd := new_udp_connection(addr, to.port);

  msg := stun_message_prepare(Stun_Message_Kind.BIND | .REQUEST);

  stun_message_send(msg, sock_fd);
}

stun_attribute_integrity :: (key: string) -> Stun_Attribute {
  header := Stun_Attribute_Header.{
    kind = .MESSAGE_INTEGRITY,
    length = 20,
  };
  value: Stun_Attribute_Value;
  attr := Stun_Attribute_Integrity.{
    key = key,
  };
  set(*value, attr);
  return .{ header, value };
}
stun_attribute_fingerprint :: () -> Stun_Attribute {
  header := Stun_Attribute_Header.{
    kind = .FINGERPRINT,
    length = 4,
  };

  value: Stun_Attribute_Value;
  attr := Stun_Attribute_Fingerprint.{ 0 };
  set(*value, attr);
  return .{ header, value };
}

stun_attribute_ice_controlled :: (tie_breaker: u64) -> Stun_Attribute {
  header := Stun_Attribute_Header.{
    kind = .ICE_CONTROLLED,
    length = 8,
  };

  value: Stun_Attribute_Value;
  attr := Stun_Attribute_IceControl.{ tie_breaker };
  set(*value, attr);
  return .{ header, value };
}

stun_attribute_priority :: (priority: u32) -> Stun_Attribute {
  header := Stun_Attribute_Header.{
    kind = .PRIORITY,
    length = 4,
  };
  value: Stun_Attribute_Value;
  attr := Stun_Attribute_Priority.{
    priority = priority,
  };
  set(*value, attr);
  return .{ header, value };
}

stun_attribute_username :: (local: string, other: string) -> Stun_Attribute {
  header := Stun_Attribute_Header.{
    kind = .USERNAME,
    length = xx (local.count + other.count + 1),
  };
  value: Stun_Attribute_Value;
  attr := Stun_Attribute_Username.{
    remote = other,
    local = local,
  };
  set(*value, attr);
  return .{ header, value };
}

stun_attribute_mapped :: (sock_addr: Socket_Address) -> Stun_Attribute {
  // we don't care about ipv6
  // @scope support ipv6
  header := Stun_Attribute_Header.{
    kind = .MAPPED_ADDRESS,
    length = 8,
  };

  value: Stun_Attribute_Value;
  set(*value, Stun_Attribute_Mapped.{
    port = sock_addr.port,
    addr = Ip_Address.{.IPV4, sock_addr.addr.ip_addr},
  });

  return .{
    header = header,
    value = value,
  };
}

stun_attribute_xor_mapped :: (sock_addr: Socket_Address) -> Stun_Attribute {
  // we don't care about ipv6
  // @scope support ipv6
  header := Stun_Attribute_Header.{
    kind = .XOR_MAPPED_ADDRESS,
    length = 8,
  };

  value: Stun_Attribute_Value;
  set(*value, Stun_Attribute_Mapped.{
    port = sock_addr.port,
    addr = sock_addr.addr,
  });
  return .{
    header = header,
    value = value,
  };
}
_new_transaction_id :: () -> (u32, u64) #expand {
  r_get :: _cryptographically_secure_random_bytes;
  return xx r_get(4).data, xx r_get(8).data;
}

_cryptographically_secure_random_bytes :: ($N: int) -> [N]u8 {
  bytes: [N]u8;
  assert(RAND_bytes(bytes.data, bytes.count) != -1, "Error generating random bytes\n");
  return bytes;
}


// made clacker write the printing code because i ain't spending time doing allat
to_string :: (header: Stun_Header) -> string #expand {
  builder := String_Builder.{allocator = temp};
  print_to_builder(*builder, "{\n");
  print_to_builder(*builder, "    kind: %,\n", cast(Stun_Message_Kind)header.kind);
  print_to_builder(*builder, "    length: %,\n", header.length);
  print_to_builder(*builder, "    magic_cookie: 0x%,\n", formatInt(header.magic_cookie, base=16));
  print_to_builder(*builder, "    transaction_id: %_%,\n",
    formatInt(BYTE_SWAP(header.transaction_id.first), base=16),
    formatInt(BYTE_SWAP(header.transaction_id.second), base=16)
  );
  print_to_builder(*builder, "  }");
  return builder_to_string(*builder);
}

to_string :: (message: Stun_Message) -> string #expand {
    temp_builder := String_Builder.{allocator = temp};
    builder := *temp_builder;
    print_to_builder(builder, "STUN message {\n");
    print_to_builder(builder, "  header: %\n", to_string(message.header));
    print_to_builder(builder, "  attributes: [\n");

    for attr: message.attributes {
        print_to_builder(builder, "    {\n");
        print_to_builder(builder, "      kind: %,\n", attr.header.kind);
        print_to_builder(builder, "      length: %,\n", attr.header.length);

        if attr.header.kind == {
          case .MAPPED_ADDRESS;  #through;
          case .XOR_MAPPED_ADDRESS; {
            mapped := isa(attr.value, Stun_Attribute_Mapped);
            assert(mapped != null);

            print_to_builder(builder, "      value: {\n");
            print_to_builder(builder, "        family: %,\n", mapped.addr.family);
            print_to_builder(builder, "        port: %,\n", mapped.port);
            print_to_builder(builder, "        addr: %,\n", to_string(mapped.addr));
            print_to_builder(builder, "      }\n");
          }
          case .USERNAME; {
            username_attr := isa(attr.value, Stun_Attribute_Username);
            assert(username_attr != null);

            print_to_builder(builder, "      value: {\n");
            print_to_builder(builder, "        remote:  %,\n", username_attr.remote);
            print_to_builder(builder, "        local: %,\n", username_attr.local);
            print_to_builder(builder, "      }\n");
          }
          case .MESSAGE_INTEGRITY; #through;
          case .ERROR_CODE; #through;
          case .UNKNOWN_ATTRIBUTES; #through;
          case .REALM; #through;
          case .NONCE; print_to_builder(builder, "      value: <unparsed> %\n", attr.header.kind);

          case; print_to_builder(builder, "      value: <unknown>\n");

        }
        print_to_builder(builder, "    },\n");
    }

    print_to_builder(builder, "  ]\n");
    print_to_builder(builder, "}\n");

    return builder_to_string(builder);
}

#scope_file

#import "Basic";
#import "Bit_Operations";
#import "Linux";
#import "Log";
#import "Net";
#import "OpenSSL";
#import "Random";
#import "Socket";
#import "String";
#import "Tagged_Union";
#import "utils";
#import "Hash_Table";
#import "Hash";
