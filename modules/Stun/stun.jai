MAGIC_COOKIE :: cast(u32)0x2112A442;

MTU :: 1504; // TODO(shahzad): @fixme query this on runtime but tbh do we really
             // even need this? stun requests are far more smaller than this

Stun_Header_Type_Sane :: enum u16 {
  REQUEST                  ::  0x0;
  INDICATION               ::  0x01;
  SUCESS_RESPONSE          ::  0x10;
  ERROR_RESPONSE           ::  0x11;
};

STUN_HEADER_TYPE_BIT_C0 :: 1 << 4;
STUN_HEADER_TYPE_BIT_C1 :: 1 << 8;

Stun_Header_Type :: enum_flags u16 {
  REQUEST                       ::  0x0;
  INDICATION                    ::  STUN_HEADER_TYPE_BIT_C0;
  SUCESS_RESPONSE               ::  STUN_HEADER_TYPE_BIT_C1;
  ERROR_RESPONSE                ::  STUN_HEADER_TYPE_BIT_C0 | STUN_HEADER_TYPE_BIT_C1;

  BIND                          ::  0x1;

};

Stun_Header :: struct {
  Pair :: struct (t1: $T, t2: $T2) {
    first: t1;
    second: t2;
  } #no_padding;

  type: u16;
  length:  u16;
  magic_cookie: u32;
  transaction_id: Pair(u64, u32);
} #no_padding;
#assert size_of(Stun_Header) == 20;

Stun_Attribute_Type :: enum u16 {
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
  type: Stun_Attribute_Type;
  length: u16;
};

Stun_None_Attribute :: void;

Stun_Mapped_Attribute :: struct {
  family: enum u16 { IPV4 :: 1; IPV6 :: 2; };
  using #as addr_info: SocketAddress;
};

Stun_Username_Attribute :: struct {
  username, password: string;
}

Stun_Attribute_Value :: Tagged_Union(Stun_None_Attribute, Stun_Mapped_Attribute, Stun_Username_Attribute);

Stun_Attribute :: struct {
  header: Stun_Attribute_Header;
  value: Stun_Attribute_Value;
};

Stun_Message :: struct {
  header: Stun_Header;
  attributes: [..]Stun_Attribute;
};

length_align :: (length: $T, alignment := 4) -> T #expand {
  a :: alignment;
  return ifx length % a != 0  length + a - (length % a) else length;
}

stun_header_sane_type :: (header: *Stun_Header) -> Stun_Header_Type_Sane {
  type :u32 = header.type;
  mask :u32 = xx (STUN_HEADER_TYPE_BIT_C0 | STUN_HEADER_TYPE_BIT_C1);
  as_sane : u32 = 0;
  #asm {
     pext as_sane, type, mask;
  }
  _sane := as_sane;
  return xx _sane;
}


stun_message_serialize :: (res: []u8) -> Stun_Message {
  assert(res.count >= 20, tprint("stun message should atleast be 20 bytes, given % bytes!", res.count));
  parsed_message: Stun_Message;
  res_header := cast(*Stun_Header)res.data;

  type := stun_header_sane_type(res_header);

  if type == {
    case .REQUEST;{}
    case .INDICATION; assert(false, "INDICATION is not implemented!");
    case .SUCESS_RESPONSE; assert(res_header.type & xx Stun_Header_Type.BIND != 0);
    case .ERROR_RESPONSE; assert(false, "ERROR_RESPONSE is not implemented!");
  }
  // TODO(shahzad): we do not parse method and assume that the server will only send the bind one

  parsed_message.header = .{
    type = xx BYTE_SWAP(res_header.type),
    length = BYTE_SWAP(res_header.length),
    magic_cookie = BYTE_SWAP(res_header.magic_cookie),
    transaction_id.first = res_header.transaction_id.first,
    transaction_id.second = res_header.transaction_id.second, // idk why but we don't have to do swap
  };

  builder: String_Builder;
  str := to_string(*builder, parsed_message.header);
  assert(parsed_message.header.length & 0b11 == 0); // the value is padded to be multiple of 4 bytes

  // skip the payload first
  attribute_view := array_view(res, size_of(Stun_Header), res.count);

  bytes_consumed_while_parsing_attrs := 0;
  while bytes_consumed_while_parsing_attrs < parsed_message.header.length {
    attr : Stun_Attribute;
    attr_header: Stun_Attribute_Header;
    attr_value: Stun_Attribute_Value;

    attr_header = .{
      type = xx BYTE_SWAP(attribute_view.data.(*u16).*),
      length = BYTE_SWAP((attribute_view.data + 2).(*u16).*),
    };
    bytes_consumed_while_parsing_attrs += 4;
    attr.header = attr_header;

    if attr_header.type == {
      case .XOR_MAPPED_ADDRESS; {
          attribute_value_view := array_view(attribute_view, size_of(Stun_Attribute_Header), res.count);
          value := Stun_Mapped_Attribute.{
            family =  xx (attribute_value_view.data + 1).(*u8).*,
            port = xx BYTE_SWAP(BYTE_SWAP((attribute_value_view.data + 2).(*u16).*) ^ cast(u16) (MAGIC_COOKIE >> 16)),
            addr = .{ ip_addr = BYTE_SWAP(BYTE_SWAP((attribute_value_view.data + 4).(*u32).*) ^ MAGIC_COOKIE)},
          };

          assert(value.family == .IPV4, "we do not support IPV6 at all!"); // right now atleast

          set(*attr_value, value);
      }
      case .USERNAME; {
        attribute_value_view := array_view(attribute_view, size_of(Stun_Attribute_Header), res.count);
        username_password := cast(string)attribute_value_view;
        username_password.count = attr_header.length;
        ok, username, password := split_from_left(username_password, ":");
        assert(ok);
        value := Stun_Username_Attribute.{
          username = username,
          password = password,
        };
        set(*attr_value, value);
      }
    case; {
      if attr_header.type < 0x8000 {
        // we don't care about them atp
        print("required attr_type % is unimplimented!\n", formatInt(cast(u16)attr_header.type, 16));
        // assert(false, tprint("required attr_type % is unimplimented!", attr_header.type));
      }
      print("optional attr_type % is unimplimented!\n", formatInt(cast(u16)attr_header.type, 16));
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

Bytes_Writer :: struct {
  cursor: s64;
  bytes: []u8;
};

write_bytes :: (using writer: *Bytes_Writer, data: $T) {
  (bytes.data + cursor).(*T).* = data;
  cursor += size_of(T);
}

write_string :: (using writer: *Bytes_Writer, str: string) {
  memcpy(bytes.data + cursor, str.data, str.count);
  cursor += str.count;
}

stun_message_deserialize :: (msg: *Stun_Message) -> string {
  total_length := msg.header.length + size_of(Stun_Header);
  deserialized := alloc_string(total_length);
  writer:= Bytes_Writer.{
    cursor = 0,
    bytes =  xx deserialized,
  };

  write_bytes(*writer, BYTE_SWAP(msg.header.type));
  write_bytes(*writer, BYTE_SWAP(msg.header.length));
  write_bytes(*writer, BYTE_SWAP(msg.header.magic_cookie));
  write_bytes(*writer, msg.header.transaction_id.first);
  write_bytes(*writer, msg.header.transaction_id.second);

  for msg.attributes {
    header := it.header;
    value := it.value;

    write_bytes(*writer, BYTE_SWAP(cast(u16)header.type));
    write_bytes(*writer, BYTE_SWAP(header.length));

    if value.tag == {
      case Stun_Mapped_Attribute;
        as_mapped_attr := isa(value, Stun_Mapped_Attribute); assert(as_mapped_attr != null);
        if it.header.type == .XOR_MAPPED_ADDRESS {

          write_bytes(*writer, BYTE_SWAP(cast(u16)as_mapped_attr.family));
          write_bytes(*writer, BYTE_SWAP(BYTE_SWAP(cast(u16)as_mapped_attr.port) ^ cast(u16)(MAGIC_COOKIE >> 16)));
          write_bytes(*writer, BYTE_SWAP(BYTE_SWAP(as_mapped_attr.addr.ip_addr) ^ MAGIC_COOKIE));
        }else {
          write_bytes(*writer, BYTE_SWAP(cast(u16)as_mapped_attr.family));
          write_bytes(*writer, BYTE_SWAP(cast(u16)as_mapped_attr.port));
          write_bytes(*writer, BYTE_SWAP(cast(u32)as_mapped_attr.addr.ip_addr));
        }
      case Stun_Username_Attribute;
        as_username_attr := isa(value, Stun_Username_Attribute); assert(as_username_attr != null);
        write_string(*writer, as_username_attr.username);
        write_string(*writer, ":");
        write_string(*writer, as_username_attr.password);
    }
  }
  return deserialized;
}

stun_message_try_get_attribute :: (msg: Stun_Message, type: $T) -> (bool, T) {
  undef: T = ---;
  for msg.attributes {
    value := isa(it.value, type);
    if value != null return true, value;
  }
  return false, undef;
}

stun_header_default :: (type: Stun_Header_Type, length: u16 = 0) -> Stun_Header {
  hi, lo := _new_transaction_id();

  return Stun_Header.{
    type = xx type,
    length = length,
    magic_cookie = MAGIC_COOKIE,
    transaction_id = .{lo, hi},
  };
}

stun_message_prepare :: (type: Stun_Header_Type, attributes: ..Stun_Attribute) -> Stun_Message {
  total_length: u16 = 0;
  for attributes total_length += length_align(it.header.length) + size_of(Stun_Attribute_Header);
  
  msg := Stun_Message.{
    header = stun_header_default(type, total_length),
  };
  array_add(*msg.attributes, ..attributes);
  return msg;
}


stun_message_send :: (from: Socket, to: SocketAddress, msg: *Stun_Message) -> bool {
  deser := stun_message_deserialize(msg);
  udp_write(from, to, xx deser);
  return true;
}

send_binding_request :: (to: *SocketConnection) -> bool {
  addr := server.addrs[0];
  sock_fd := new_udp_connection(addr, to.port);

  msg := stun_message_prepare(Stun_Header_Type.BIND | .REQUEST);

  stun_message_send(msg, sock_fd);
}

stun_attribute_xor_username :: (sock_addr: SocketAddress) -> Stun_Attribute {
  // we don't care about ipv6
  // @scope support ipv6
  header := Stun_Attribute_Header.{
    type = .XOR_MAPPED_ADDRESS,
    length = 8,
  };

  value: Stun_Attribute_Value;
  set(*value, Stun_Mapped_Attribute.{
    family = .IPV4,
    port = sock_addr.port,
    addr = IpAddress.{sock_addr.addr.ip_addr},
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
to_string :: (builder: *String_Builder, header: Stun_Header) -> string #expand {
    print_to_builder(builder, "{\n");
    print_to_builder(builder, "    type: %,\n", cast(Stun_Header_Type)header.type);
    print_to_builder(builder, "    length: %,\n", header.length);
    print_to_builder(builder, "    magic_cookie: 0x%,\n", formatInt(header.magic_cookie, base=16));
    print_to_builder(builder, "    transaction_id: %_%,\n",
      formatInt(header.transaction_id.first, base=16),
      formatInt(header.transaction_id.second, base=16)
    );
    print_to_builder(builder, "  }");

    return builder_to_string(builder);
}

to_string :: (builder: *String_Builder, message: Stun_Message) -> string #expand {
    temp_builder: String_Builder;
    print_to_builder(builder, "STUN message {\n");
    print_to_builder(builder, "  header: %\n", to_string(*temp_builder, message.header));
    print_to_builder(builder, "  attributes: [\n");

    for attr: message.attributes {
        print_to_builder(builder, "    {\n");
        print_to_builder(builder, "      type: %,\n", attr.header.type);
        print_to_builder(builder, "      length: %,\n", attr.header.length);

        if attr.header.type == {
          case .MAPPED_ADDRESS;  #through;
          case .XOR_MAPPED_ADDRESS; {
            mapped := isa(attr.value, Stun_Mapped_Attribute);
            assert(mapped != null);

            print_to_builder(builder, "      value: {\n");
            print_to_builder(builder, "        family: %,\n", mapped.family);
            print_to_builder(builder, "        port: %,\n", mapped.port);
            print_to_builder(builder, "        addr: %,\n", to_string(mapped.addr));
            print_to_builder(builder, "      }\n");
        }
        case .USERNAME; #through;
        case .MESSAGE_INTEGRITY; #through;
        case .ERROR_CODE; #through;
        case .UNKNOWN_ATTRIBUTES; #through;
        case .REALM; #through;
        case .NONCE; print_to_builder(builder, "      value: <unparsed> %\n", attr.header.type);

        case; print_to_builder(builder, "      value: <unknown>\n");
        
        }
        print_to_builder(builder, "    },\n");
    }

    print_to_builder(builder, "  ]\n");
    print_to_builder(builder, "}\n");

    return builder_to_string(builder);
}


big_endian :: () -> bool #expand {
  x: u16 = 1;
  y := cast(*u8)*x;
  if y[0] return false;
  return true;
}
#if #run !big_endian() BYTE_SWAP :: byte_swap; else BYTE_SWAP ::  (input: $T) -> T { return input; };


#import "Basic";
#import "Random";
#import "Bit_Operations";
#import "Socket";
#import "Net";
#import "Linux";
#import "POSIX";
#import "OpenSSL";
#import "Tagged_Union";
#import "String";
