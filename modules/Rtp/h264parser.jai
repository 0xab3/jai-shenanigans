Nalu_Context :: struct {
  bytes: []u8;
}
BYTES_3 := u8.[0, 0, 1];
BYTES_4 := u8.[0, 0, 0, 1];

nalu_context_init :: (bytes: []u8) -> Nalu_Context {
  starting := find_index_from_left(xx bytes, xx BYTES_3);
  return .{
    array_view(bytes, starting),
  };
}

extract_nalu :: (ctx: *Nalu_Context) -> ([]u8, bool) {
  if ctx.bytes.count <= 3 return .[], false;

  _eat_start_code(ctx);

  next_startcode_idx := _get_startcode_index(ctx);

  nalu := array_view(ctx.bytes, 0, next_startcode_idx);

  _skip_n_bytes(ctx, next_startcode_idx);

  start_code_size := _get_startcode_size(ctx);

  if start_code_size == 4 _skip_n_bytes(ctx, 1);
  else if start_code_size == 0 {}


  return nalu, true;
}


_skip_n_bytes :: (ctx: *Nalu_Context, n: s64) {
  ctx.bytes = array_view(ctx.bytes, n);
}

_get_startcode_size :: (ctx: *Nalu_Context) -> s64 {
  if starts_with(xx ctx.bytes, xx BYTES_3) return 3;
  else if starts_with(xx ctx.bytes, xx BYTES_4) return 4;
  else if ctx.bytes.count == 0 return 0;
  assert(false, "man... this assumes that the startcode is in the first bytes of the ctx...");
  return 0;
}

_eat_start_code :: (ctx: *Nalu_Context) {
  assert(starts_with(xx ctx.bytes, xx BYTES_3));
  _skip_n_bytes(ctx, 3);
}

_get_startcode_index :: (ctx: *Nalu_Context) -> s64 {
  start_code_idx := find_index_from_left(xx ctx.bytes, xx BYTES_3); assert(start_code_idx != 0);
  if start_code_idx == -1 return ctx.bytes.count;
  if ctx.bytes[start_code_idx - 1] == 0 {
    return start_code_idx - 1;
  }
  return start_code_idx;
}


#scope_file
#import "Basic";
#import "String";
