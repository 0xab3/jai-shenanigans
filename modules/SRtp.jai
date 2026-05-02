
// SRTP_AES128_CM_HMAC_SHA1_80
//       cipher: AES_128_CM
//       cipher_key_length: 128
//       cipher_salt_length: 112
//       maximum_lifetime: 2^31
//       auth_function: HMAC-SHA1
//       auth_key_length: 160
//       auth_tag_length: 80


SRTP_Key_Block :: struct {
  client_write_SRTP_master_key: []u8; // 16
  server_write_SRTP_master_key: []u8; // 16
  client_write_SRTP_master_salt: []u8; // 14
  server_write_SRTP_master_salt: []u8; // 14
  entire: []u8; // dynamic ig?
}
SRTP_Role :: enum {CLIENT; SERVER;};
SRTP_Context :: struct {
  role: SRTP_Role;
  dtls: *DTLS_Context;
  key_block: SRTP_Key_Block;
  master_write_key: []u8;
  master_salt: []u8;

  ssrc: u32;
};


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

// chat is x label or what??
PRF_128 :: (master_key: []u8, x: []u8, gen_n_bytes: s64) -> []u8
{
  n_bytes := (gen_n_bytes + 0xf) & ~0xf;
  // A keystream segment SHALL be the concatenation of the 128-bit output
  // blocks of the AES cipher in the encrypt direction, using key k = k_e,
  // in which the block indices are in increasing order.  Symbolically,
  // each keystream segment looks like

  // E(k, IV) || E(k, IV + 1 mod 2^128) || E(k, IV + 2 mod 2^128) ...

  // where the 128-bit integer value IV SHALL be defined by the SSRC, the
  // SRTP packet index i, and the SRTP session salting key k_s, as below.

  // IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
  

  out: []u8 = xx alloc_string(n_bytes);

  iv := x;
  ctx := aes128_ctr_ctx_init(master_key, iv);


  to_encrypt: [16]u8; // encrypting 16 zeros
  memset(to_encrypt.data, 0, to_encrypt.count);
  for 0 .. (n_bytes / 16) - 1 {
    view := array_view(out, it * 16, 16);
    outlen := aes128_encrypt(ctx, to_encrypt, view); assert(outlen == 16);
  }
  finish := aes128_ctr_encrypt_finish(ctx);
  return array_view(out, 0, gen_n_bytes);
}


key_derivation :: (using srtp_ctx: *SRTP_Context)  {
  // @Note that for a key_derivation_rate of 0, the application of the key derivation SHALL take place exactly once.

  K_E_LABEL :: 0x00;
  K_A_LABEL :: 0x01;
  K_S_LABEL :: 0x02;
  
  // we do not care about the first 2 shits because key
  // derivation rate is basically 0 for us which makes
  // r = 0 and key_id = <label>
  // Let r = index DIV key_derivation_rate
  // Let key_id = <label> || r.
  // Let x = key_id XOR master_salt, where key_id and master_salt are
  // aligned so that their least significant bits agree (right-
  // alignment).



  master_salt_16_padded: []u8 = xx alloc_string(16,, allocator = temp);

  memcpy(master_salt_16_padded.data, master_salt.data, master_salt.count);
  // print("master_key %\n",master_write_key);
  // print("master_salt %\n", master_salt);

  print("this is padded %\n", hex_array(master_salt_16_padded));


  x_ke: []u8 = xx copy_string(xx master_salt_16_padded);
  x_ke[7] ^= K_E_LABEL; 

  x_ka: []u8 = xx copy_string(xx master_salt_16_padded);
  x_ka[7] ^= K_A_LABEL;

  x_ks: []u8 = xx copy_string(xx master_salt_16_padded);
  x_ks[7] ^= K_S_LABEL;

  enc_key := PRF_128(master_write_key, x_ke, 16);
  print("enc_key is this %\n", enc_key);

  auth_key := PRF_128(master_write_key, x_ka, 20);
  salting_key := PRF_128(master_write_key, x_ks, 14);

  print("salting_key is this %\n", salting_key);
  print("auth_key is this %\n", auth_key);

  // print("enc_key %\n", enc_key);
  // print("auth_key %\n", auth_key);
  // print("salthing_key %\n", salting_key);
}

// xor :: (x1: []u8, x2: $T) -> []u8 {
//   as_bytes_padded := alloc_string(x1.count);
//   as_bytes := int_to_bytes(16, x2);
// 
//   copy_offset := as_bytes_padded.count - as_bytes.count;
//   memcpy(as_bytes.data + copy_offset, as_bytes.data, as_bytes.count); 
// 
//   return xor(x1, as_bytes_padded);
// }

xor :: (x1: []u8, x2: []u8) -> []u8 {
  assert(x1.count == x2.count);
  result: []u8 = xx alloc_string(x1.count);
  for x1 result[it_index] = x1[it_index] ^ x2[it_index];
  return result;
}

// @note we only need exporter so we do not need to own this struct as of now
// we can probably yeet this
srtp_init :: (dtls_ctx: *DTLS_Context, role: SRTP_Role = .CLIENT, ssrc: u32 = 3477136883) -> SRTP_Context {

  assert(role == .CLIENT);

  MASTER_KEY_LENGTH :: 16;
  MASTER_SALT_LENGTH :: 14;
  export_length := 2 * (MASTER_KEY_LENGTH + MASTER_SALT_LENGTH);
  assert(export_length == 60);

  key_block_as_bytes := dtls_exporter(dtls_ctx, "EXTRACTOR-dtls_srtp", export_length);

  key_block := SRTP_Key_Block.{
    client_write_SRTP_master_key = xx array_view(key_block_as_bytes, 0, 16),
    server_write_SRTP_master_key = xx array_view(key_block_as_bytes, 16, 16),
    client_write_SRTP_master_salt = xx array_view(key_block_as_bytes, 32,  14),
    server_write_SRTP_master_salt = xx array_view(key_block_as_bytes, 46,  14),
    entire = key_block_as_bytes,
  };

  master_key: []u8;
  master_salt: []u8;
  if role == .CLIENT {
    master_key = key_block.client_write_SRTP_master_key;
    master_salt = key_block.client_write_SRTP_master_salt;
  } else {
    master_key = key_block.server_write_SRTP_master_key;
    master_salt = key_block.server_write_SRTP_master_salt;
  }

  print("--------------------SRTP--------------------\n");
  print("master_key : %\n", master_key);
  print("master_salt : %\n", master_salt);
  ctx :=  SRTP_Context.{ role, dtls_ctx, key_block, master_key, master_salt, ssrc };
  key_derivation(*ctx);
  return ctx;
}

#scope_file
#import "DTLS";
#import "utils";
#import "Basic";
#import "OpenSSL";
