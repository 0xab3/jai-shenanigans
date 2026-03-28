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

Stun_Header_Type :: enum u16 {
  _C0 :: 1 << 4;
  _C1 :: 1 << 8;

  REQUEST                       ::  0x0;
  INDICATION                    ::  _C0;
  SUCESS_RESPONSE               ::  _C1;
  ERROR_RESPONSE                ::  _C0 | _C1;

  BIND                          ::  0x1;
};

Stun_Header :: struct {
  Pair :: struct (t1: $T, t2: $T2) {
    first: t1;
    second: t2;
  } #no_padding;

  type: u16;
  length:  u16; // exclude header (@important length & 0x11 should be zero for stun)
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
Stun_Xor_Mapped_Attribute :: struct {
  family: Stun_Address_Family; // first 8 bits are 0
  x_port: u16;
  x_addr: IpAddress;
};

Stun_Payload :: struct {
  attr: *Stun_Attribute_Header;
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
  print("wrote % bytes to udp\n",bytes_written);
  assert(bytes_written == len,
      tprint("socket failed written %, wanted %, %", bytes_written, len, errno()));
}

udp_send :: (socket: s32, data: []u8){
  bytes_written := send(socket, data.data, xx data.count, 0);
  assert(bytes_written == data.count,
      tprint("socket failed written %, wanted %, %", bytes_written, data.count, errno()));
}
udp_recv :: (socket: s32, buf: *[]u8) -> s64 {
  sz := recv(socket, buf.data, xx buf.count, xx 0);
  print("recvd %\n",sz);
  assert(sz > 0);
  return sz;
}

send_binding_request :: (server: *Stun_Server_Info) {
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

  read_header := cast(*Stun_Header)slice.data;

  assert(read_header.type & xx Stun_Header_Type.SUCESS_RESPONSE != 0 && read_header.type & 1 != 0);

  payload := array_view(slice, size_of(Stun_Header), slice.count);

  attr := Stun_Attribute_Header.{
    type = xx BYTE_SWAP(payload.data.(*u16).*),
    length = BYTE_SWAP((payload.data + 2).(*u16).*),
  };

  print("type %\n", attr.type);
  print("length %\n", attr.length);
  assert(attr.type == .XOR_MAPPED_ADDRESS);
  assert(attr.length == 8);

  // TODO(shahzad): this is very bad
  payload = array_view(payload, size_of(Stun_Attribute_Header), slice.count);
  xor_mapped := Stun_Xor_Mapped_Attribute.{
    family =  xx (payload.data + 1).(*u8).*,
    x_port = xx BYTE_SWAP(BYTE_SWAP((payload.data + 2).(*u16).*) ^ cast(u16) (MAGIC_COOKIE >> 16)),
    x_addr = .{ ip_addr = BYTE_SWAP(BYTE_SWAP((payload.data + 4).(*u32).*) ^ MAGIC_COOKIE)},
  };
  print("family %\n", xor_mapped.family);
  print("x_port %\n", xor_mapped.x_port);
  print("x_addr %\n", to_string(xor_mapped.x_addr));
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
