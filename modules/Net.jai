NetworkEndpoint :: struct {
  url: string;
  port: u16;
}
ResolvedEndpoints :: struct {
  url: string;
  addrs: [..]IpAddress; // a single network endpoint have multiple IPs
};

SocketConnection :: struct {
  using #as endpoint: NetworkEndpoint;
  addr: IpAddress;
  sock: Socket = xx -1;
};

IpAddress :: struct { // TODO(shahzad): @feat add ipv6
  IpV4 :: u32; // is this unix specific??
  ip_addr: IpV4;
};

SocketAddress :: struct {
  addr: IpAddress;
  port: u16;
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


#scope_file
#import "Socket";
#import "Basic";
