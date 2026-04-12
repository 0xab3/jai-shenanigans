MTU :: 1504; // TODO(shahzad): @fixme query this on runtime

Network_Interface :: struct {
  name: string;
}
Network_Endpoint :: struct {
  url: string;
  port: u16;
}
Resolved_Endpoints :: struct {
  url: string;
  addrs: [..]Ip_Address; // a single network endpoint have multiple IPs
};

Socket_Address :: struct {
  addr: Ip_Address;
  port: u16;
};

Socket_Connection :: struct {
  using #as sock_addr: Socket_Address;
  sock: Socket = xx -1;
};
Ip_Family :: enum { IPV4 :: 1; IPV6 :: 2; };

Ip_Address :: struct { // TODO(shahzad): @feat add ipv6
  IpV4 :: u32; // is this unix specific??
  family: Ip_Family;
  ip_addr: IpV4;
};

socket_address_from_sockaddr :: (addr: sockaddr_in) -> Socket_Address {
  family: Ip_Family =
    ifx addr.sin_family == AF_INET then .IPV4
    else ifx addr.sin_family == AF_INET6 then .IPV6
    else { assert(false); .IPV4;};

  return .{
    port = addr.sin_port,
    addr = .{
      family = family,
      ip_addr = addr.sin_addr.s_addr,
    },
  };
}
to_string :: (addr: Ip_Address) -> string {
  // yanked from Socket/module.jai
  builder: String_Builder;
  append_address(*builder, addr.ip_addr);
  return builder_to_string(*builder);
}

// @scope ipv4 only @unsafe we do not check the length of the array
ip_addr_from_string :: (addr: string) -> Ip_Address {
  parsed_addr: in_addr;
  inet_aton(addr.data, *parsed_addr);
  return .{.IPV6, parsed_addr.s_addr};
}

udp_socket_client :: (ip: Ip_Address, port: u16) -> Socket {
  servaddr: sockaddr_in;
  servaddr.sin_addr.s_addr = xx ip.ip_addr;
  servaddr.sin_port = htons(port);
  servaddr.sin_family = AF_INET;

  sockfd := socket(AF_INET, .SOCK_DGRAM, 0);

  if connect(sockfd, cast(*sockaddr)*servaddr, size_of(type_of(servaddr))) < 0 {
      log_err("error: failed to set address to sockfd\n");
      assert(false); // this can never fail
  }

  set_blocking(xx sockfd);

  return .{ addr = ip, port = port, };
}

udp_write :: (from: Socket, to: Socket_Address, data: []u8) -> s64 {
  dest_addr := sockaddr_in.{
    sin_addr.s_addr = xx to.addr.ip_addr,
    sin_port = to.port,
    sin_family = AF_INET,
  };
  addrlen: socklen_t = size_of(sockaddr_in);
  how_much := sendto(xx from, data.data, xx data.count, 0, cast(*sockaddr)*dest_addr, addrlen);
  if how_much <= 0 log_err("failed to send data to socket %\n", errno());
  assert(how_much == data.count); // we  don't give a shit

  return how_much;
}

// @unused
udp_recv_from :: (socket: s32, buf: *[]u8) -> ([]u8, OS_Error_Code, Socket_Address) {
  assert(false);
  addr: sockaddr_in;
  len: u32 = size_of(sockaddr_in);

  sz := recvfrom(socket, buf.data, xx buf.count, xx 0,cast(*sockaddr)*addr, *len);
  if sz == -1 || sz == 0 return "", errno(), .{};

  log_debug("read % byes from udp!\n",sz);

  // @priority look into the byte order, i don't think we should ntohs port here
  sock_addr := Socket_Address.{ Ip_Address.{addr.sin_addr.s_addr}, ntohs(addr.sin_port) };

  return array_view(buf, 0, sz), 0, sock_addr;
}

#import "Socket";
#import "POSIX";

#scope_file
#import "Basic";
#import "Log";
