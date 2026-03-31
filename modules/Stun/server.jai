Stun_Server :: struct {
  endpoint: NetworkEndpoint;
  addrs: [..]IpAddress; // all of the Address that the dns resolved to
};
stun_server_info_from_network_endpoint :: (endpoint: NetworkEndpoint) -> Stun_Server {
  ok, endpoints := perform_dns_lookup(endpoint.url);
  return .{
    endpoint  =  endpoint,
    addrs     =  endpoints.addrs,
  };
}

perform_dns_lookup :: (host: string) -> (bool, ResolvedEndpoints) {
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

#import "Net";
