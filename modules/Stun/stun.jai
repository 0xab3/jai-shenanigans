MAGIC_COOKIE :: cast(u32)0x2112A442;

MTU :: 1504; // TODO(shahzad): @fixme query this on runtime but tbh do we really
             // even need this? stun requests are far more smaller than this

Stun_Server_Info :: struct {
  using #as conn: SocketConnection;
  addrs: [..]IpAddress; // all of the Address that the dns resolved to
};


//  0                 1
//  2  3  4 5 6 7 8 9 0 1 2 3 4 5
//
//  +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
//  |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
//  |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
//  +--+--+-+-+-+-+-+-+-+-+-+-+-+-+


// to get that shit we do pext_(header, bytes)

   // C1 and C0 represent a 2-bit encoding of
   // the class.  A class of 0b00 is a request, a class of 0b01 is an
   // indication, a class of 0b10 is a success response, and a class of
   // 0b11 is an error response.

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
   // (Reserved)                      :: 0x0000;
   MAPPED_ADDRESS                     :: 0x0001;
   // (Reserved; was RESPONSE-ADDRESS):: 0x0002;
   // (Reserved; was CHANGE-ADDRESS)  :: 0x0003;
   // (Reserved; was SOURCE-ADDRESS)  :: 0x0004;
   // (Reserved; was CHANGED-ADDRESS) :: 0x0005;
   USERNAME                           :: 0x0006;
   // (Reserved; was PASSWORD)        :: 0x0007;
   MESSAGE_INTEGRITY                  :: 0x0008;
   ERROR_CODE                         :: 0x0009;
   UNKNOWN_ATTRIBUTES                 :: 0x000A;
   // (Reserved; was REFLECTED-FROM)  :: 0x000B;
   REALM                              :: 0x0014;
   NONCE                              :: 0x0015;
   XOR_MAPPED_ADDRESS                 :: 0x0020;
};

Stun_Attribute_Header :: struct {
  type: Stun_Attribute_Type;
  length: u16;
};

Stun_Address_Family :: enum u16 {
  IPV4 :: 1;
  IPV6 :: 2;
};

// make this a tagged union
Stun_Mapped_Attribute :: struct {
  family: Stun_Address_Family; // first 8 bits are 0
  using #as addr_info: SocketAddress;
};

Stun_None_Attribute :: void;
Stun_Attribute_Value :: Tagged_Union(Stun_None_Attribute, Stun_Mapped_Attribute);
// this is only for convenience
Stun_Attribute :: struct {
  header: Stun_Attribute_Header;
  value: Stun_Attribute_Value;
};

Stun_Message :: struct {
  header: Stun_Header;
  attributes: [..]Stun_Attribute;
};

stun_server_info_from_network_endpoint :: (endpoint: NetworkEndpoint) -> Stun_Server_Info {
  ok, endpoints := _perform_dns_lookup(endpoint.url);
  return .{
    endpoint  =  endpoint,
    addrs     =  endpoints.addrs,
    sock      =  xx -1,
  };
}

// TODO(shahzad): @refactor use SocketConnection here
new_udp_connection :: (ip: IpAddress, port: u16) -> s32 {
  servaddr: sockaddr_in;
  servaddr.sin_addr.s_addr = xx ip.ip_addr;
  servaddr.sin_port = htons(port);
  servaddr.sin_family = AF_INET;

  sockfd := socket(AF_INET, .SOCK_DGRAM, 0);

  if connect(sockfd, cast(*sockaddr)*servaddr, size_of(type_of(servaddr))) < 0 {
      print("error: failed to set address to sockfd\n");
      assert(false); // this can never fail
  }
  return sockfd;
}

udp_send :: (socket: s32, data: *u8, len: u32){
  bytes_written := send(socket, data, xx len, 0);
  print("wrote % bytes to udp!\n",bytes_written);
  assert(bytes_written == len,
      tprint("socket failed written %, wanted %, %", bytes_written, len, errno()));
}

udp_send :: (socket: s32, data: []u8){
  bytes_written := send(socket, data.data, xx data.count, 0);
  print("wrote % bytes to udp!\n",bytes_written);
  assert(bytes_written == data.count,
      tprint("socket failed written %, wanted %, %", bytes_written, data.count, errno()));
}
udp_recv :: (socket: s32, buf: *[]u8) -> s64 {
  sz := recv(socket, buf.data, xx buf.count, xx 0);
  print("read % byes from udp!\n",sz);
  assert(sz > 0);
  return sz;
}

stun_header_get_type :: (header: *Stun_Header) -> Stun_Header_Type_Sane {
  type :u32 = header.type;
  mask :u32 = xx (STUN_HEADER_TYPE_BIT_C0 | STUN_HEADER_TYPE_BIT_C1);
  as_sane : u32 = 0;
  #asm {
     pext as_sane, type, mask;
  }
  _sane := as_sane;
  return xx _sane;
}


// made clacker write the printing code because i ain't spending doing allat
print_stun_header :: (builder: *String_Builder, header: Stun_Header) -> string #expand {
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

print_stun_message :: (builder: *String_Builder, message: Stun_Message) -> string #expand {
    temp_builder: String_Builder;
    print_to_builder(builder, "STUN message {\n");
    print_to_builder(builder, "  header: %\n", print_stun_header(*temp_builder, message.header));

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
        case .NONCE; {
            print_to_builder(builder, "      value: <unparsed> %\n", attr.header.type);
        }

        case; {
            print_to_builder(builder, "      value: <unknown>\n");
        }
        }

        print_to_builder(builder, "    },\n");
    }

    print_to_builder(builder, "  ]\n");
    print_to_builder(builder, "}\n");

    return builder_to_string(builder);
}
stun_message_parse :: (res: []u8) -> Stun_Message {
  assert(res.count >= 20, tprint("stun message should atleast be 20 bytes, given % bytes!", res.count));
  parsed_message: Stun_Message;
  res_header := cast(*Stun_Header)res.data;

  type := stun_header_get_type(res_header);

  if type == {
    case .REQUEST; assert(false, "REQUEST is not implemented!");
    case .INDICATION; assert(false, "INDICATION is not implemented!");
    case .SUCESS_RESPONSE; {
      assert(res_header.type & xx Stun_Header_Type.BIND != 0);
    };
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

  assert(parsed_message.header.length & 0x11 == 0); // the value is padded to be multiple of 4 bytes

  // skip the payload first
  attribute_view := array_view(res, size_of(Stun_Header), res.count);

  bytes_consumed_while_parsing_attrs := 0;
  while attribute_view.count > 0 {
    attr : Stun_Attribute;
    attr_header: Stun_Attribute_Header;
    attr_value: Stun_Attribute_Value;

    attr_header = .{
      type = xx BYTE_SWAP(attribute_view.data.(*u16).*),
      length = BYTE_SWAP((attribute_view.data + 2).(*u16).*),
    };
    bytes_consumed_while_parsing_attrs += 4;

    assert(attr_header.type == .XOR_MAPPED_ADDRESS);
    assert(attr_header.length == 8);

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
        bytes_consumed_while_parsing_attrs += 8;
      }
    case;
      assert(false, tprint("attr_type % is unimplimented!", attr_header.type));
    }
    attr.value = attr_value;
    array_add(*parsed_message.attributes, attr);

    attribute_view = array_view(attribute_view, size_of(Stun_Attribute_Header) + attr_header.length, attribute_view.count);
  }
  return parsed_message;
}

stun_message_try_get_mapped_address :: (msg: Stun_Message) -> (bool, Stun_Mapped_Attribute) {
  undef : Stun_Mapped_Attribute;
  for msg.attributes {
    if it.header.type == {
      case .MAPPED_ADDRESS; #through;
      case .XOR_MAPPED_ADDRESS;
        value := isa(it.value, Stun_Mapped_Attribute);
        assert(value != null);
        return true, value.*;
      case; continue;
    }
  }
  return false, undef;

}
send_binding_request :: (server: *Stun_Server_Info) -> Stun_Message {
  addr := server.addrs[0];
  sock_fd := new_udp_connection(addr, server.port);
  hi, lo := _new_transaction_id();

  header := Stun_Header.{
    type = xx BYTE_SWAP(Stun_Header_Type.BIND | .REQUEST),
    length = 0,
    magic_cookie = BYTE_SWAP(MAGIC_COOKIE),
    transaction_id = .{lo, hi},
  };

  udp_send(sock_fd, xx *header, size_of(type_of(header)));
  bytes := alloc(512);
  slice: []u8;
  slice.data = xx bytes;
  slice.count = 512;

  size := udp_recv(sock_fd, *slice);
  slice.count = size;
  
  msg := stun_message_parse(slice);

  sb: String_Builder;
  print("response\n");
  print("--------------------------------------------------\n");
  print("%", print_stun_message(*sb, msg));
  print("--------------------------------------------------\n");


  return msg;
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

_perform_dns_lookup :: (host: string) -> (bool, ResolvedEndpoints) {
  ip_addrs: [..]IpAddress;
  result: *addrinfo;
  hints: addrinfo = .{
    ai_family = PF_UNSPEC,
    ai_socktype = .STREAM,
    ai_flags = .CANONNAME,
  };

  err := getaddrinfo (to_c_string(host), null, *hints, *result);
  if err != 0 {
    print("failed: getaddrinfo()! %d", err);
    return false, .{ host, ip_addrs };
  }

  iter := result;
  while iter != null {
    if iter.ai_family == AF_INET6 {
      print("we do not support IPV6!\n"); // for now atleast
      iter = iter.ai_next;
      continue;
    }
    as_inet := cast(*sockaddr_in)iter.ai_addr;

    print("IPv%d address: % (%)\n", ifx iter.ai_family == PF_INET6 6 else 4,
          to_string(as_inet), to_string(iter.ai_canonname));

    array_add(*ip_addrs, .{ as_inet.sin_addr.s_addr });
    iter = iter.ai_next;
  }
  freeaddrinfo(result);
  return true, .{ host, ip_addrs };
}

big_endian :: () -> bool #expand {
  x: u16 = 1;
  y := cast(*u8)*x;
  if y[0] return false;
  return true;
}
#if #run !big_endian() BYTE_SWAP :: byte_swap; else BYTE_SWAP ::  (input: $T) -> T { return input; };


#import "Random";
#import "Basic";
#import "Bit_Operations";
#import "Socket";
#import "Net";
#import "Linux";
#import "POSIX";
#import "OpenSSL";
#import "Tagged_Union";
