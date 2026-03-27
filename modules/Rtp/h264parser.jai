extract_nalu :: (payload : []u8) -> ([]u8, []u8, bool) {
  undef: []u8 = .[];

  if payload.count >= 3 {
    first_start_code_idx := find_index_from_left(cast(string)payload, cast(string)u8.[0, 0, 1]);
    if first_start_code_idx == -1 return undef, undef, false;

    start_code_length := 3;
    next := find_index_from_left(cast(string)array_view(payload, 3), cast(string)u8.[0, 0, 1]);
    if next == -1 {
      next = payload.count;       // if we don't find next startcode make it last
      start_code_length = 0;
    } else if payload[next - 1] == 0 {
      next -= 1; // if we find startcode and it's 4byte remove extra 0
      start_code_length = 4;
    }
    assert(next != -1);
    nalu := array_view(payload, 3,  next);
    return nalu, array_view(payload, next + start_code_length), true;
  }
  return undef, undef, false;
}

#import "Basic";
#import "String";
