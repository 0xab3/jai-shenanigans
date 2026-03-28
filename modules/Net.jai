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

to_string :: (addr: IpAddress) -> string {
  as_inet := sockaddr_in.{
    sin_family = AF_INET,
    sin_port = 0,
  };
  as_inet.sin_addr.s_addr = xx addr.ip_addr;
  return to_string(as_inet);
}


#scope_file
#import "Socket";
