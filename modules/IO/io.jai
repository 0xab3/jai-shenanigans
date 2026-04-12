// i ain't writing IO_Uring wrappers
MAX_EVENTS :: 36; // remove this please

Event_Kind :: enum_flags {
  READ: EPOLLIN; // udp writes are nonblocking
};

IO :: struct {
  timeout: u32;
  epoll_fd: s32;
  events: [MAX_EVENTS]epoll_event;
}

io_init :: (max_ops := 36, timeout := 1) -> IO {
  return .{
    epoll_fd = epoll_create(max_ops),
    timeout = timeout,
  };
}

io_add_event :: (io: IO, fd: s32, kind: Event_Kind, udata: *void) {
  data = epoll_data.{.ptr = udata };
  event = epoll_event.{ events = xx kind, data = data, };

  if epoll_ctl(io.epoll_fd, .ADD, event.fd, &event.inner) == -1 {
    log_err("epoll_ctl: error is this %\n", errno());
    assert(false, "unreachable!"); // for now
  } 
}

io_read_event :: (io: IO, fd: s32) {
  io_add_event(io, fd, .READ);
}

io_tick :: (io: IO) -> []epoll_event {
  n_ready_fds := epoll_wait(io.epoll_fd, io.events, MAX_EVENTS, io.timeout);
  if n_ready_fds == -1 {
    log_err("epoll_wait: error is this %\n", errno());
    assert(false, "unreachable!"); // for now
  }
  return array_view(io.events, 0, n_ready_fds);
}


#scope_file
#import "Linux";
#import "POSIX";
#import "Log";
