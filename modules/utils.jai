Pair :: struct (T: Type, T2: Type) {
  first: T;
  second: T2;
} #no_padding;

Bytes_Writer :: struct {
  cursor: s64;
  bytes: []u8;
  should_swap: bool;
};

bytes_writer_new :: (buf: []u8) -> Bytes_Writer {
  return .{
    bytes = buf,
    should_swap = true,
  };
}

write_bytes :: (using writer: *Bytes_Writer, data: $T) {
  assert(cursor - 1 + size_of(T) <= bytes.count);
  _data := data;
  if should_swap _data = byte_swap(data);
  (bytes.data + cursor).(*T).* = _data;
  cursor += size_of(T);
}

write_string :: (using writer: *Bytes_Writer, str: string) {
  assert(cursor - 1 + str.count <= bytes.count, tprint("% % %\n", cursor - 1, str.count, bytes.count));
  memcpy(bytes.data + cursor, str.data, str.count);
  cursor += str.count;
}

Bytes_Reader :: struct {
  cursor: s64;
  bytes: []u8;
  should_swap: bool = true;
};

read_bytes_inplace :: (using reader: *Bytes_Reader, x: *$T) {
  assert(cursor - 1 + size_of(T) <= bytes.count,
    tprint("% % %\n", cursor - 1, size_of(T), bytes.count)
  );
  _read: T = (bytes.data + cursor).(*T).*;
  cursor += size_of(T);
  if reader.should_swap _read = byte_swap(_read);
  x.* = _read;
}

read_bytes :: (using reader: *Bytes_Reader, $T: Type) -> T {
  assert(cursor - 1 + size_of(T) <= bytes.count,
    tprint("% % %\n", cursor - 1, size_of(T), bytes.count)
  );
  _read: T = (bytes.data + cursor).(*T).*;
  cursor += size_of(T);
  if reader.should_swap _read = byte_swap(_read);
  return _read;
}

reflection_array_copy :: (arr: *[]u8, idx: s64, elem: *void, info: *Type_Info) {
  assert(info.runtime_size > 0);
  byte_idx := idx * info.runtime_size;
  maybe_grow(xx arr, info.runtime_size);
  memcpy(arr.data + byte_idx, elem, info.runtime_size);
}

reflection_array_add :: (arr: *[]u8, elem: *void, info: *Type_Info) {
  assert(info.runtime_size > 0);
  byte_idx := arr.count;
  maybe_grow(xx arr, info.runtime_size);
  memcpy(arr.data + byte_idx, elem, info.runtime_size);
  arr.count += info.runtime_size;
}

reflection_struct_set_field :: (info: *Type_Info_Struct, name: string, data: *u8, value: *u8) {
  member := get_field(info, name);
  if !member unreachable("no member named % in struct %\n",name, info.name);
  reflection_struct_set_field(member, data, value);
}
reflection_struct_set_field :: (member: *Type_Info_Struct_Member, data: *u8, value: *u8) {
  memcpy(data + member.offset_in_bytes, value, member.offset_in_bytes);
}

byte_swap_inplace :: (data: *u8, sz: s64) {
  if sz == {
    case 1; return;
    case 2; as_int_ptr := data.(*u16); as_int_ptr.* = byte_swap(as_int_ptr.*);
    case 4; as_int_ptr := data.(*u32); as_int_ptr.* = byte_swap(as_int_ptr.*); 
    case 8; as_int_ptr := data.(*u64); as_int_ptr.* = byte_swap(as_int_ptr.*); 
    case;
      unreachable("unknown size %\n", sz);
  }
}

// this should be named as any as to implies that this converts the type
// instead this only converts the representation ykwim
to_any :: (concrete :*$T) -> Any #expand {
  as_any: Any;
  as_any.type = type_info(type_of(concrete.*));
  as_any.value_pointer = concrete;
  return as_any;
}
// ik about polymorphism but we ain't doing that
read_string_no_copy :: (using reader: *Bytes_Reader, sz: s64) -> []u8 {
  assert(cast(s64)(cursor - 1 + sz) <= bytes.count,
    tprint("% %\n", cursor - 1 + sz, bytes.count),
  );
  _read: []u8;
  _read.count = sz;
  _read.data = bytes.data + cursor;
  cursor += sz;
  return _read;
}

read_string :: (using reader: *Bytes_Reader, $SZ: s64) -> [SZ]u8 {
  assert(cast(s64)(cursor - 1 + SZ) <= bytes.count,
    tprint("% %\n", cursor - 1 + SZ, bytes.count),
  );
  _read: [SZ]u8;
  memcpy(_read.data, bytes.data + cursor, SZ);
  cursor += SZ;

  return _read;
}
hex_array :: (value: [] u8) -> string {
    builder: String_Builder;
    print_to_builder(*builder,"[");
    for value {
      if (it >> 4) & 0xf == 0 print_to_builder(*builder, "0%, ", formatHex(it));
      else print_to_builder(*builder, "%, ", formatHex(it));
    }
    print_to_builder(*builder,"]");
    return builder_to_string(*builder);
}

hex_string :: (value: [] u8) -> string {
    builder: String_Builder;
    for value {
      if (it >> 4) & 0xf == 0 print_to_builder(*builder, "0%", formatHex(it));
      else print_to_builder(*builder, "%", formatHex(it));
    }
    return builder_to_string(*builder);
}

int_to_bytes :: (data: $T) -> []u8 {
  n_bytes := 0;

  dta := data;
  while dta > 0 { dta /= 10; n_bytes += 1; }

  buf := alloc_string(n_bytes);

  for 0..buf.count-1 {
    buf[it] = cast(u8)((data >> ((N  - it - 1)  * 8)) & 0xff);
  }
}

int_to_bytes :: ($N: s64, data: $T) -> [N]u8 {
  buf: [N]u8;
  for 0..buf.count-1 {
    buf[it] = cast(u8)((data >> ((N  - it - 1)  * 8)) & 0xff);
  }
  return buf;
}

pointer_to_view :: (data: *void, count: s64, $T: Type = u8) -> []T {
  res: T;
  res.data = xx data;
  res.count = count;
  return res;
}
bytes_to_int :: (buf: []u8, $T: Type) -> T {
  res: T;
  for 0..buf.count-1 {
    res = (res << 8) | buf[it];
  }
  return res;
}
bytes_to_int :: (buf: [$N]u8, $T: Type) -> T {
  res: T;
  for 0..buf.count-1 {
    res = (res << 8) | buf[it];
  }
  return res;
}

random_n_bytes :: ($N: s64) -> [N]u8 {
  bytes: [N]u8;
  random_bytes(*array_view(bytes, 0, N));
  return bytes;
}
random_bytes :: (bytes: *[]u8) #expand {
  assert(bytes.count != 0);
  n_words := bytes.count / 8;
  remaining := bytes.count % 8;
  for 0..n_words-1 {
    (cast(*u64)bytes.data + it).* = random_get();
  }
  for 1..remaining {
    (bytes.data + bytes.count - it).* = cast,no_check(u8)random_get(); // we are going reverse but who cares
  }
}


unreachable :: (fmt: string, args: ..Any) #expand {
  builder: String_Builder;
  print_to_builder(*builder, fmt, ..args,, allocator = temp);
  msg := builder_to_string(*builder);
  assert(false, msg);
}
unreachable :: (msg: string) #expand {
  assert(false, msg);
}

strerror :: (err: OS_Error_Code) -> string {
  return to_string(hstrerror(err));
}

formatHex :: #bake_arguments formatInt(base=16);

big_endian :: () -> bool #expand {
  x: u16 = 1;
  y := cast(*u8)*x;
  if y[0] return false;
  return true;
}
// @remove this should be a runtime thing properly managed by
// options in bytes_reader
#if #run !big_endian() BYTE_SWAP :: byte_swap; else BYTE_SWAP ::  (input: $T) -> T { return input; };

#scope_file
#import "Basic";
#import "Bit_Operations";
#import "Random";
#import "POSIX";
#import "Linux";
#import "Socket";
#import "String";
