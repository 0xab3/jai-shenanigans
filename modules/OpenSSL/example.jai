HOST :: "tsoding.github.io";
PORT :: "443";

main :: () {
  hints: addrinfo;
  hints.ai_family = AF_INET;
  hints.ai_socktype = .STREAM;
  hints.ai_protocol = .TCP;

  addrs: *addrinfo;
  if getaddrinfo(HOST, PORT, *hints, *addrs) < 0 {
    print("ERROR: Could not get adress of `%:%`", HOST, PORT);
    exit(1);
  }

  addr := addrs;
  sd: s32 = 0;
  while addr != null {
    sd = socket(addr.ai_family, addr.ai_socktype, addr.ai_protocol);

    if sd == -1 break;
    if connect(sd, addr.ai_addr, addr.ai_addrlen) == 0 break;

    close(sd);
    sd = -1;
    addr = addr.ai_next;
  }
  freeaddrinfo(addrs);

  if sd == -1 {
    print("Could not connect to %:%", HOST, PORT);
    exit(1);
  }

  ret := OpenSSL_add_all_algorithms();
  assert(ret == 1);
  ret = SSL_load_error_strings();
  assert(ret == 1);
  ctx := SSL_CTX_new(TLS_client_method());
  if ctx == null {
    print("ERROR: could not initialize SSL context\n");
    exit(1);
  }

  ssl := SSL_new(ctx);
  if ssl == null {
    print("ERROR: could not create SSL structure\n");
    exit(1);
  }
  ret = SSL_set_fd(ssl, sd);
  assert(ret == 1);

  if SSL_connect(ssl) < 0 {
    print("ERROR: could not connect to %:% via SSL\n", HOST, PORT);
    exit(1);
  }

  request :: "GET / HTTP/1.0\r\nHost: tsoding.github.io\r\n\r\n";

  SSL_write(ssl, request.data, request.count);

  buffer := NewArray(1024, u8);
  n := SSL_read(ssl, buffer.data, xx buffer.count);
  while n > 0 {
    print("%", to_string(buffer.data, n));
    n = SSL_read(ssl, buffer.data, xx buffer.count);
  }

  print("OK!\n");
}
