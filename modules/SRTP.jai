SRTP_Protection_Profile :: enum u16 {
  AES128_CM_HMAC_SHA1_80 :: 0x01;
};

SRTP_Extension :: struct {
  profiles: []SRTP_Protection_Profile;

  // we do not care as of now to be honest
  // mki: https://datatracker.ietf.org/doc/html/rfc3711#section-3.1
  srtp_mki: []u8; // 0..255
};

srtp_get_extensions :: (profiles: ..SRTP_Protection_Profile, mki: []u8 = .[]) -> DTLS_Extension {
  writer := Bytes_Writer.{should_swap = true};

  total_length := 3 + profiles.count * 2; // 1 is for mki.count

  // @leak
  writer.bytes = xx alloc_string(total_length);

  write_bytes(*writer, cast(u16)profiles.count * 2);

  for profiles write_bytes(*writer, cast,force(u16)it);

  assert(mki.count == 0);
  write_bytes(*writer, cast(u8)mki.count);
  if mki.count > 0 write_string(*writer, xx mki);

  return DTLS_Extension.{
    kind = .SRTP_EXTENSION,
    data = writer.bytes,
  };
}

#scope_file
#import "DTLS";
#import "utils";
#import "Basic";
