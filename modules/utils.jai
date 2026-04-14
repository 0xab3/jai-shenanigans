Pair :: struct (T: Type, T2: Type) {
  first: T;
  second: T2;
} #no_padding;

Bytes_Writer :: struct {
  cursor: s64;
  bytes: []u8;
};

write_bytes :: (using writer: *Bytes_Writer, data: $T) {
  (bytes.data + cursor).(*T).* = data;
  cursor += size_of(T);
}

write_string :: (using writer: *Bytes_Writer, str: string) {
  memcpy(bytes.data + cursor, str.data, str.count);
  cursor += str.count;
}

Bytes_Reader :: struct {
  cursor: s64;
  bytes: []u8;
  should_swap: bool = true;
};


read_bytes :: (using reader: *Bytes_Reader, $T: Type) -> T {
  _read: T = (bytes.data + cursor).(*T).*;
  cursor += size_of(T);
  if reader.should_swap _read = byte_swap(_read);
  return _read;
}

// ik about polymorphism but we ain't doing that
read_string_no_copy :: (using reader: *Bytes_Reader, sz: s64) -> []u8 {
  assert(cast(s64)(cursor + sz) <= bytes.count,
    tprint("% %\n", cursor + sz, bytes.count),
  );
  _read: []u8;
  _read.count = sz;
  _read.data = bytes.data + cursor;
  return _read;
}
read_string :: (using reader: *Bytes_Reader, $SZ: s64) -> [SZ]u8 {
  assert(cast(s64)(cursor + SZ) <= bytes.count,
    tprint("% %\n", cursor + SZ, bytes.count),
  );
  _read: [SZ]u8;
  memcpy(_read.data, bytes.data + cursor, SZ);
  cursor += SZ;

  return _read;
}

hex_string :: (value: [] u8) -> string {
    builder: String_Builder;
    for value {
        print_to_builder(*builder, "%", formatHex(it));
    }
    return builder_to_string(*builder);
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

#import "Basic";
#import "Bit_Operations";
