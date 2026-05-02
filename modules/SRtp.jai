
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

SRTP_Session_Keys :: struct {
  enc_key: []u8;
  salt_key: []u8;
  auth_key: []u8;

};

SRTP_Context :: struct {
  role: SRTP_Role;
  dtls: *DTLS_Context;
  key_block: SRTP_Key_Block;
  master_write_key: []u8;
  master_salt: []u8;

  ssrc: u32;
  sender: RTP_Sender;

  sm_buffer: [..]u8;

  session_keys: SRTP_Session_Keys; // not for reading i think
};

SRTP_Packet :: struct {
  using #as header: RTP_Header;
  payload: []u8;
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


// @todo this should be a frame or sample having more info than this shit
write_srtp :: (ctx: *SRTP_Context, nalu: []u8, timestamp: u32) {
  RTP_HEADER_LENGTH :: size_of(RTP_Header);

  pkt := rtp_packet_new(*ctx.sender, nalu, timestamp);

  encrypted := encrypt_rtp_packet(ctx, pkt);

  AUTH_TAG_LENGTH :: 10;
  packet_len := encrypted.payload.count + size_of(RTP_Header) + AUTH_TAG_LENGTH;
  
  serialized: []u8 = xx alloc_string(packet_len);

  memcpy(serialized.data, xx *encrypted.header, RTP_HEADER_LENGTH);
  memcpy(serialized.data + RTP_HEADER_LENGTH , encrypted.payload.data, encrypted.payload.count);



  sha_ctx := sha1_init(ctx.session_keys.auth_key);
  

  to_hash_data := array_view(serialized, 0, serialized.count - AUTH_TAG_LENGTH);
  sha1_update(sha_ctx, to_hash_data);


  // ROC shit we ain't doing allat
  sha1_update(sha_ctx, array_view(u8.[0,0,0,0], 0, 4));

  auth_tag: [AUTH_TAG_LENGTH]u8;
  sum := sha1_final(sha_ctx);
  memcpy(auth_tag.data, sum.data, auth_tag.count);


  memcpy(serialized.data + RTP_HEADER_LENGTH + encrypted.payload.count, auth_tag.data, auth_tag.count);

  bytes_written := conn_udp_write(ctx.sender.conn, serialized);
  assert(bytes_written == packet_len);
}

encrypt_rtp_packet :: (ctx: *SRTP_Context, pkt: RTP_Packet) -> SRTP_Packet {
  out_pkt: SRTP_Packet = .{ pkt.header, .[] };
  out_pkt.payload = ctx.sm_buffer;
  out_pkt.payload.count = pkt.payload.count;

  to_encrypt := pkt.payload;


  session_keys := ctx.session_keys;

  seq_no := BYTE_SWAP(pkt.seq_no);
  ssrc := BYTE_SWAP(pkt.ssrc);


  ssrc_as_bytes: []u8 = xx alloc_string(10);
  memset(ssrc_as_bytes.data, 0, ssrc_as_bytes.count);
  memcpy(ssrc_as_bytes.data, int_to_bytes(4, ssrc).data, 4);
  seq_no_as_bytes := int_to_bytes(4, seq_no);

  // IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
  temp_ctx := context;
  temp_ctx.allocator = temp;

  iv_: []u8;
  push_context temp_ctx {
    iv_ = xor(xor(session_keys.salt_key, seq_no_as_bytes), ssrc_as_bytes);
  }

  iv: []u8 = xx alloc_string(16,, allocator = temp);
  memcpy(iv.data, iv_.data, iv_.count);

  aes_ctx := aes128_ctr_ctx_init(session_keys.enc_key, iv);

  outlen := aes128_encrypt(aes_ctx, to_encrypt, out_pkt.payload);

  finish := aes128_ctr_encrypt_finish(aes_ctx);

  return out_pkt;

}
// chat is x label or what??
PRF_128 :: (master_key: []u8, x: []u8, gen_n_bytes: s64) -> []u8 {
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
  in: []u8 = xx alloc_string(n_bytes,, allocator = temp);
  memset(in.data, 0, in.count);


  iv := x;
  ctx := aes128_ctr_ctx_init(master_key, iv);
  outlen :=  aes128_encrypt(ctx, in, out);
  finish := aes128_ctr_encrypt_finish(ctx);
  return array_view(out, 0, gen_n_bytes);
}


key_derivation :: (using srtp_ctx: *SRTP_Context) {
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
  salt_key := PRF_128(master_write_key, x_ks, 14);

  print("salt_key is this %\n", salt_key);
  print("auth_key is this %\n", auth_key);

  // print("enc_key %\n", enc_key);
  // print("auth_key %\n", auth_key);
  // print("salthing_key %\n", salting_key);
  srtp_ctx.session_keys = .{
    enc_key = enc_key,
    salt_key = salt_key,
    auth_key = auth_key,
  };
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
  max_iter := max(x1.count, x2.count);
  result: []u8 = xx alloc_string(max_iter);
  i := 1;
  while i <= x1.count && i <= x2.count {
    result[result.count - i] = x1[x1.count - i] ^ x2[x2.count - i];
    i += 1;
  }

  while i <= x1.count {
    result[result.count - i] = x1[x1.count - i] ^ 0;
    i += 1;
  }

  while i <= x2.count {
    result[result.count - i] = 0 ^ x2[x2.count - i];
    i += 1;
  }

  return result;
}

// @note we only need exporter so we do not need to own this struct as of now
// we can probably yeet this
srtp_init :: (dtls_ctx: *DTLS_Context, conn: Socket_Connection, role: SRTP_Role = .CLIENT, ssrc: u32 = 3477136883) -> SRTP_Context {

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
  rtp_sender := RTP_Sender.{ ssrc = ssrc, conn = conn };
  ctx :=  SRTP_Context.{ 
    role = role,
    dtls = dtls_ctx,
    key_block = key_block,
    master_write_key = master_key,
    master_salt = master_salt,
    ssrc = ssrc,
    sender = rtp_sender,
  };

  array_reserve(*ctx.sm_buffer, 10 * 1024);

  key_derivation(*ctx);
  return ctx;
}

#scope_file
#import "DTLS";
#import "utils";
#import "Basic";
#import "OpenSSL";
#import "Rtp";
#import "Net";
