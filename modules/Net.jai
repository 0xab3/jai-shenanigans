NetworkEndpoint :: struct {
  url: string;
  port: u16;
}
ResolvedEndpoints :: struct {
  url: string;
  addrs: [..]IpAddress; // a single network endpoint have multiple IPs
};

SocketAddress :: struct {
  addr: IpAddress;
  port: u16;
};

SocketConnection :: struct {
  using #as sock_addr: SocketAddress;
  sock: Socket = xx -1;
};

IpAddress :: struct { // TODO(shahzad): @feat add ipv6
  IpV4 :: u32; // is this unix specific??
  ip_addr: IpV4;
};


to_string :: (addr: IpAddress) -> string {
  // yanked from Socket/module.jai
  builder: String_Builder;
  append_address(*builder, addr.ip_addr);
  return builder_to_string(*builder);
}

// @scope ipv4 only @unsafe we do not check the length of the array
ip_addr_from_string :: (addr: string) -> IpAddress {
  parsed_addr: in_addr;
  inet_aton(addr.data, *parsed_addr);
  return .{parsed_addr.s_addr};
}



// TODO(shahzad): @refactor use SocketConnection here
new_udp_connection :: (ip: IpAddress, port: u16) -> SocketConnection {
  servaddr: sockaddr_in;
  servaddr.sin_addr.s_addr = xx ip.ip_addr;
  servaddr.sin_port = htons(port);
  servaddr.sin_family = AF_INET;

  sockfd := socket(AF_INET, .SOCK_DGRAM, 0);

  if connect(sockfd, cast(*sockaddr)*servaddr, size_of(type_of(servaddr))) < 0 {
      print("error: failed to set address to sockfd\n");
      assert(false); // this can never fail
  }

  assert(false, "unimplemented!");
  return .{  };
}

udp_write :: (from: Socket, to: SocketAddress, data: []u8) -> s64 {
  dest_addr := sockaddr_in.{
    sin_addr.s_addr = xx to.addr.ip_addr,
    sin_port = htons(to.port),
    sin_family = AF_INET,
  };
  addrlen: socklen_t = size_of(sockaddr_in);
  how_much := sendto(xx from, data.data, xx data.count, 0, cast(*sockaddr)*dest_addr, addrlen);
  if how_much <= 0 print("failed to send data to socket %\n", errno());
  assert(how_much == data.count); // we  don't give a shit

  return how_much;
}
udp_recv_from :: (socket: s32, buf: *[]u8) -> (s64, SocketAddress) {
  addr: sockaddr_in;
  len: u32 = size_of(sockaddr_in);

  sz := recvfrom(socket, buf.data, xx buf.count, xx 0,cast(*sockaddr)*addr, *len);
  print("read % byes from udp!\n",sz);
  assert(sz > 0);

  sock_addr := SocketAddress.{
    addr = IpAddress.{addr.sin_addr.s_addr},
    port = addr.sin_port,
  };

  return sz, sock_addr;
}

#scope_file
#import "Socket";
#import "Basic";
#import "POSIX";
