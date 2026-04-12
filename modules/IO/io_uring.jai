// we wrote an IO_Uring wrapper :sob:
IO_Uring_Params :: io_uring_params;
IO_Uring_SQE :: io_uring_sqe;
IO_Uring_CQE :: io_uring_cqe;
IO_Uring_GetEvents_Arg :: io_uring_getevents_arg;
// because highlighting tastes better than lines
Time_Spec :: timespec;

IOURING_ENTRIES :: 128;

Submission_Queue :: struct {
  head: *u32;
  tail: *u32;
  mask: u32;
  array: *u32;
  flags: *u32;
  entries: []IO_Uring_SQE;
};

Completion_Queue :: struct {
  head: *u32;
  tail: *u32;
  mask: u32;
  flags: *u32;
  entries: []IO_Uring_CQE;
};

IO_Uring :: struct {
  fd: s32;
  ring_base_ptr: *void;
  ring_size: u64;
  flags: IORING_Setup_Flags;
  s_queue: Submission_Queue;
  c_queue: Completion_Queue;
};

IO_Uring_Error :: enum {
  Success;
  AllocationFailed;
};

uring_init :: (uring: *IO_Uring, params: *IO_Uring_Params) -> IO_Uring_Error {
  assert(!(params.flags & IORING_Setup_Flags.IORING_SETUP_CQE32), "no");
  uring.* = IO_Uring.{
    fd = io_uring_setup(IOURING_ENTRIES, params),
    flags = params.flags,
  };
  assert(!(params.flags & IORING_Setup_Flags.IORING_SETUP_CQE32), "no");

  // stolen from the man page
  submission_ring_size: int =
      params.sq_off.array + params.sq_entries * size_of(u32);
  completion_ring_size: int =
    params.cq_off.cqes + params.cq_entries * size_of(IO_Uring_CQE);
  // we don't give a single shit about kernel version < 5.14
  // TODO(shahzad): @scope add support for kernel version < 5.14
  assert(params.features & IORING_FEAT_SINGLE_MMAP != 0);
  // kernel < 5.4 require that the data should be valid until completion
  // but fuck that
  assert(params.features & IORING_FEAT_SUBMIT_STABLE != 0);

  submission_ring_size = xx max(submission_ring_size, completion_ring_size);
  uring.ring_size = xx submission_ring_size;
  io_ring := mmap(null, uring.ring_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
           uring.fd, IORING_OFF_SQ_RING);

  if io_ring == MAP_FAILED return .AllocationFailed;

  uring.s_queue.head = io_ring + params.sq_off.head;
  uring.s_queue.tail = io_ring + params.sq_off.tail;
  uring.s_queue.mask = (io_ring + params.sq_off.ring_mask).(*u32).*;
  uring.s_queue.array = io_ring + params.sq_off.array;
  uring.s_queue.flags = io_ring + params.sq_off.flags;
  uring.s_queue.entries.data =
    mmap(null, params.sq_entries * size_of(IO_Uring_SQE), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, uring.fd, IORING_OFF_SQES);
  uring.s_queue.entries.count = params.sq_entries;

  if uring.s_queue.entries.data == MAP_FAILED return .AllocationFailed;

  uring.c_queue.head = io_ring + params.cq_off.head;
  uring.c_queue.tail = io_ring + params.cq_off.tail;
  uring.c_queue.mask = (io_ring + params.cq_off.ring_mask).(*u32).*;
  uring.c_queue.entries.data = io_ring + params.cq_off.cqes;
  uring.c_queue.entries.count = params.cq_entries;

  uring.ring_base_ptr = io_ring;
  return 0;
}

uring_deinit :: (using uring: *IO_Uring) {
    munmap(ring, ring_size);
    munmap(s_queue.entries.data, xx (s_queue.entries.count * size_of(IO_Uring_SQE)));
    close(fd);
}

uring_submit :: (uring: *IO_Uring, wait_nr: u32 = 0, timeout: *timespec = null) -> u32, OS_Error_Code {
  arg: IO_Uring_GetEvents_Arg;
  arg.ts = xx timeout;
  sq_entries := sq_ready(uring);
  if sq_entries > 0 && (sq_ring_needs_enter(uring) || wait_nr > 0) {
    ret, err := __io_uring_enter(uring, sq_entries, wait_nr, xx IORING_ENTER_GETEVENTS, *arg);
    return ret, err;
  }
  // idk what to do in this scenario
  return 0, 0;
}

sq_ring_needs_enter :: (using uring: *IO_Uring) -> bool {
  // @todo implement this (i don't understand this so i am leaving it like his)
  assert(atomic_read(s_queue.flags) & xx IORING_SQ_NEED_WAKEUP == 0);
  return true;
}
sq_ready :: (using uring: *IO_Uring) -> u32 {
  return s_queue.tail.* - atomic_read(s_queue.head);
}

sqe_get :: (using uring: *IO_Uring) -> *IO_Uring_SQE {
  head := atomic_read(s_queue.head);
  if (cast(int)atomic_read(s_queue.tail) - cast(int)head) > s_queue.entries.count {
    return null; // we are cooked
  }

  tail := atomic_add(s_queue.tail, 1);
  index := tail & s_queue.mask;

  sqe := *s_queue.entries[index];
  s_queue.array[index] = index;

  return sqe;
}

cq_ready :: (using uring: *IO_Uring) -> u32 {
  return atomic_read(c_queue.tail) - c_queue.head.*;
}

cq_advance :: (using uring: *IO_Uring, count: u32) {
  if count == 0 return;
  atomic_write(c_queue.head, c_queue.head.* + count);
}

cq_ring_needs_flush :: (using uring: *IO_Uring) -> bool {
  return IORING_SQ_CQ_OVERFLOW & xx atomic_read(s_queue.flags) != 0;
}

cqes_copy :: (using uring: *IO_Uring, cqes: []IO_Uring_CQE, wait_nr: u32) -> []IO_Uring_CQE, OS_Error_Code {
  copied := cqes_copy_ready(uring, cqes);
  if copied.count > 0 return copied, 0;
  if wait_nr > 0 || cq_ring_needs_flush(uring) {
    n_entries, err := __io_uring_enter(uring, 0, wait_nr, xx IORING_ENTER_GETEVENTS);
    if err != 0 return .[], err;
    copied = cqes_copy_ready(uring, cqes);
  }
  return copied, 0;
}

cqes_copy_ready :: (using uring: *IO_Uring, cq: []IO_Uring_CQE) -> []IO_Uring_CQE {
  // @refactor casts are crazy in this bro
  n_ready := cq_ready(uring);
  to_copy := cast(s32) min(n_ready, cast(u32)cq.count);

  head := c_queue.head.*;

  for 0..to_copy-1    cq[it] = c_queue.entries[(head + xx it) & c_queue.mask];

  cq_advance(uring, xx to_copy);
  return array_view(cq, 0, xx to_copy);
}

uring_op_recvmsg :: (uring: *IO_Uring, fd: s32, hdr: *msghdr, flags: MSG ,userdata: *void) -> *IO_Uring_SQE {
  sqe := sqe_get(uring);
  if sqe == null return null;

  sqe.opcode = .IORING_OP_RECVMSG;
  sqe.fd = fd;
  sqe.addr = xx hdr;
  sqe.other_flags = xx flags; // the union does not have the msg_flag that's why using another member
  sqe.user_data = xx userdata;
  sqe.recv_send_flags = 0;
  return sqe;
}


uring_op_read :: (uring: *IO_Uring, fd: s32, buf: []u8, userdata: *void) -> *IO_Uring_SQE {
  sqe := sqe_get(uring);
  if !sqe return null;
  sqe.* = .{
    opcode = .IORING_OP_READ,
    fd = fd,
    off = 0,
    addr = xx buf.data,
    len = xx buf.count,
    user_data = xx userdata,
  };
  return sqe;
}

uring_op_timeout :: (uring: *IO_Uring, timeout: *Time_Spec, userdata: *void) -> *IO_Uring_SQE {
  sqe := sqe_get(uring);
  if !sqe return null;
  sqe.* = .{
    opcode = .IORING_OP_TIMEOUT,
    fd = -1,
    addr = xx timeout,
    len = 1,
    user_data = xx userdata,
    off = 0,
  };
  return sqe;
}

// me and my homies hate private
__io_uring_enter :: inline (uring: *IO_Uring, to_submit: u32, min_complete: u32, flags: u32) -> u32, OS_Error_Code {
  ret := cast(s32)syscall(SYS_io_uring_enter, uring.fd, to_submit, min_complete, flags, null);
  if ret < 0 return 0, xx -ret;
  return xx ret, 0;

}
__io_uring_enter :: inline (uring: *IO_Uring, to_submit: u32, min_complete: u32, flags: u32, sig: *sigset_t) -> u32, OS_Error_Code {
  ret := cast(s32)syscall(SYS_io_uring_enter, uring.fd, to_submit, min_complete, flags, sig);
  if ret < 0 return 0, xx -ret;
  return xx ret, 0;
}
__io_uring_enter :: inline (uring: *IO_Uring, to_submit: u32, min_complete: u32, flags: u32, arg: *io_uring_getevents_arg) -> u32, OS_Error_Code {
  ret := cast(s32)syscall(SYS_io_uring_enter, uring.fd, to_submit, min_complete, flags | xx IORING_ENTER_EXT_ARG, arg, size_of(io_uring_getevents_arg));
  if ret < 0 return 0, xx -ret;
  return xx ret, 0;
}

#scope_file

#import "Linux";
#import "Socket";
#import "Basic";
#import "POSIX";
#import "Atomics";
#import "Log";
