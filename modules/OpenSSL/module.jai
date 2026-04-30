// stolen from tsoding https://gist.github.com/rexim/ab45940928399bbda212185b4a6a6339
libssl :: #system_library "libssl";
libcrypto :: #system_library "libcrypto";

OPENSSL_INIT_ADD_ALL_CIPHERS ::        0x00000004;
OPENSSL_INIT_ADD_ALL_DIGESTS ::        0x00000008;
OPENSSL_INIT_LOAD_CONFIG ::            0x00000040;

OPENSSL_INIT_LOAD_SSL_STRINGS ::       0x00200000;
OPENSSL_INIT_LOAD_CRYPTO_STRINGS ::    0x00000002;

OPENSSL_init_crypto :: (opts: u64, settings: *void) -> s32 #foreign libcrypto;
OPENSSL_init_ssl :: (opts: u64, settings: *void) -> s32 #foreign libssl;

SSL_METHOD       ::  void;
SSL_CTX          ::  void;
SSL              ::  void;
X509_STORE       ::  void;
X509             ::  void;
X509_STORE_CTX   ::  void;
BIO              ::  void;
EVP_PKEY         ::  void;
EVP_PKEY_CTX     ::  void;
EVP_MD_CTX       ::  void;
EVP_MD           ::  void;
ENGINE           ::  void;
EC_KEY           ::  void;
EC_GROUP         ::  void;
SHA_LONG         ::  u32;
SHA_LBLOCK       ::  16;

SHA256_CTX :: struct {
    h:      [8] u32;
    Nl:     u32;
    Nh:     u32;
    data:   [16] u32;
    num:    u32;
    md_len: u32;
};

TLS_client_method :: () -> *SSL_METHOD #foreign libssl;
SSL_CTX_new :: (meth: *SSL_METHOD) -> *SSL_CTX #foreign libssl;
SSL_new :: (ctx: *SSL_CTX) -> *SSL #foreign libssl;
SSL_set_fd :: (ssl: *SSL, fd: s32) -> s32 #foreign libssl;
SSL_connect :: (ssl: *SSL) -> s32 #foreign libssl;
SSL_write :: (ssl: *SSL, buf: *void, num: s32) -> s32 #foreign libssl;
SSL_read :: (ssl: *SSL, buf: *void, num: s32) -> s32 #foreign libssl;
SSL_get_error :: (ssl: *SSL, ret: s32) -> s32 #foreign libssl;
ERR_get_error :: () -> s32 #foreign libssl;
ERR_error_string :: (ret: s32, buf: *u8) -> *u8 #foreign libssl;
RAND_bytes :: (buf: *u8, num: s32) -> s32 #foreign libcrypto;
HMAC :: (evp_md: *EVP_MD, key: *u8, key_len: s32, data: *u8, data_len: u64,
                    md: *u8, md_len: *u32) -> *u8 #foreign libssl;
EVP_sha1 :: () -> *EVP_MD #foreign libssl;

EVP_MD_CTX_new :: () -> *EVP_MD_CTX #foreign libcrypto;
EVP_MD_CTX_free :: (ctx: *EVP_MD_CTX) -> void #foreign libcrypto;

EVP_sha256 :: () -> *EVP_MD #foreign libcrypto;

EVP_DigestVerifyInit :: (ctx: *EVP_MD_CTX, pctx: *void, type: *EVP_MD, e: *void, pkey: *EVP_PKEY) -> s32 #foreign libcrypto;
EVP_DigestVerifyUpdate :: (ctx: *EVP_MD_CTX, data: *void, len: s64) -> s32 #foreign libcrypto;
EVP_DigestVerifyFinal :: (ctx: *EVP_MD_CTX, sig: *u8, siglen: s64) -> s32 #foreign libcrypto;

X509_get_pubkey :: (cert: *X509) -> *EVP_PKEY #foreign libssl;

// useless
BIO_new_mem_buf :: (buf: *void, len: s32) -> *BIO #foreign libssl;

X509_STORE_new :: () -> *X509_STORE #foreign libssl;
X509_STORE_set_default_paths :: (s: *X509_STORE) -> s32 #foreign libssl;
X509_STORE_load_locations :: (s: *X509_STORE, file: *u8, dir: *u8) -> s32 #foreign libssl;
PEM_read_bio_X509 :: (out: *BIO, x: **X509, cb: *void, udata: *void) -> *void #foreign libssl;
PEM_read_X509 :: (out: *FILE, x: **X509, cb: *void, udata: *void) -> *void #foreign libssl;
PEM_read_PrivateKey :: (out: *FILE, x: **EVP_PKEY, pem_password_cb: *void, udata: *void) -> *EVP_PKEY #foreign libssl;



d2i_X509 :: (x: **void, in: **u8, len: s64) -> *X509 #foreign libssl;
X509_STORE_CTX_new :: () -> *X509_STORE_CTX #foreign libssl;
X509_STORE_CTX_init :: (ctx: *X509_STORE_CTX, trust_store: *X509_STORE,
    target: *X509, untrusted: *void) -> s32 #foreign libssl;
X509_verify_cert :: (ctx: *X509_STORE_CTX) -> s32 #foreign libssl;
X509_STORE_CTX_get_error :: (ctx: *X509_STORE_CTX) -> s32 #foreign libssl;
X509_verify_cert_error_string :: (n: s32) -> *u8 #foreign libssl;
X509_free :: (ptr: *X509) #foreign libssl;


EVP_PKEY_CTX_new_id :: (id: s32, e: *void) -> *EVP_PKEY_CTX #foreign libcrypto;
EVP_PKEY_CTX_new    :: (pkey: *EVP_PKEY, e: *void) -> *EVP_PKEY_CTX #foreign libcrypto;
EVP_PKEY_CTX_free   :: (ctx: *EVP_PKEY_CTX) -> void #foreign libcrypto;

EVP_PKEY_keygen_init :: (ctx: *EVP_PKEY_CTX) -> s32 #foreign libcrypto;
EVP_PKEY_keygen      :: (ctx: *EVP_PKEY_CTX, ppkey: **EVP_PKEY) -> s32 #foreign libcrypto;
EVP_PKEY_free :: (key: *EVP_PKEY) -> void #foreign libcrypto;

EVP_PKEY_CTX_set_ec_paramgen_curve_nid :: (ctx: *EVP_PKEY_CTX, nid: s32) -> s32 #foreign libcrypto;

EVP_PKEY_derive_init     :: (ctx: *EVP_PKEY_CTX) -> s32 #foreign libcrypto;
EVP_PKEY_derive_set_peer :: (ctx: *EVP_PKEY_CTX, peer: *EVP_PKEY) -> s32 #foreign libcrypto;
EVP_PKEY_derive          :: (ctx: *EVP_PKEY_CTX, key: *u8, keylen: *u64) -> s32 #foreign libcrypto;
EVP_PKEY_get_id          :: (k: *EVP_PKEY) -> s32 #foreign libcrypto;

EVP_PKEY_get0_EC_KEY :: (pkey : *EVP_PKEY) -> *EC_KEY #foreign libcrypto;
EC_KEY_get0_group :: (key: *EC_KEY) -> *EC_GROUP #foreign libcrypto;
EC_GROUP_get_curve_name :: (group: *EC_GROUP) -> s32 #foreign libcrypto;
OBJ_nid2sn :: (n: s32) -> *u8 #foreign libcrypto;



d2i_PUBKEY :: (a: *EVP_PKEY, pp: **u8, length: s64) -> *EVP_PKEY #foreign libcrypto;
d2i_PrivateKey_fp :: (fp: *FILE, idk: *void) -> *EVP_PKEY #foreign libcrypto;
i2d_PUBKEY :: (pkey: *EVP_PKEY, pp: **u8) -> s32 #foreign libcrypto;
EVP_PKEY_get_raw_public_key :: (pkey: *EVP_PKEY, buf: *u8, len: *s32) -> s32 #foreign libcrypto;
EVP_PKEY_new_raw_public_key :: (type: s32, e: *ENGINE, key: *u8, keylen: s64) -> *EVP_PKEY #foreign libcrypto;
i2d_PrivateKey :: (pkey: *EVP_PKEY, pp: **u8) -> s32 #foreign libcrypto;
EVP_PKEY_get0_type_name :: (pkey: *EVP_PKEY) -> *u8 #foreign libcrypto;


EVP_PKEY_X25519      :: 1034;
EVP_PKEY_ED25519     :: 1087;
NID_X9_62_prime256v1 :: 415;

EVP_DigestSignInit :: (ctx: *EVP_MD_CTX, pctx: **EVP_PKEY_CTX, type: *void, e: *ENGINE, pkey: *EVP_PKEY) -> s32 #foreign libcrypto;
EVP_DigestSignUpdate :: (ctx: *EVP_MD_CTX, data: *void, dlen: s32) -> s32 #foreign libcrypto;
EVP_DigestSignFinal :: (ctx: *EVP_MD_CTX, sig: *u8, siglen: *s32) -> s32 #foreign libcrypto;

SHA256_HASH_LENGTH :: 32;
SHA256_DIGEST_LENGTH :: SHA256_HASH_LENGTH;
SHA256 :: (d: *u8, n: u64, md: *u8) -> *u8 #foreign libssl;
SHA256_Init   :: (c: *SHA256_CTX) -> s32 #foreign libcrypto;
SHA256_Update :: (c: *SHA256_CTX, data: *void, len: u64) -> s32 #foreign libcrypto;
SHA256_Final  :: (md: *u8, c: *SHA256_CTX) -> s32 #foreign libcrypto;

EVP_CIPHER :: void;
EVP_CIPHER_CTX :: void;

EVP_CTRL_GCM_SET_IVLEN :: 09;
AES_GCM_IV_SIZE        :: 12;
AES_GCM_TAG_SIZE       :: 16;
EVP_CTRL_GCM_GET_TAG   :: 0x10;
 
EVP_CIPHER_CTX_new :: () -> *EVP_CIPHER_CTX #foreign libcrypto;
EVP_CIPHER_CTX_free :: (ctx: *EVP_CIPHER_CTX) #foreign libcrypto;
EVP_aes_128_gcm :: () -> *EVP_CIPHER  #foreign libcrypto;
EVP_EncryptInit_ex :: (ctx: *EVP_CIPHER_CTX, cipher: *EVP_CIPHER, engine: *void, key: *u8, iv: *u8) -> s32 #foreign libcrypto;
EVP_EncryptUpdate :: (ctx: *EVP_CIPHER_CTX, out: *u8, outl: *s32, in: *u8, inl: s32) -> s32 #foreign libcrypto;
EVP_EncryptFinal_ex :: (ctx: *EVP_CIPHER_CTX, outm: *u8, outl: *s32) -> s32 #foreign libcrypto;
EVP_CIPHER_CTX_ctrl :: (ctx: *EVP_CIPHER_CTX, type: s32, arg: s32, ptr: *void)-> s32 #foreign libcrypto;


EVP_DecryptInit_ex :: (ctx: *EVP_CIPHER_CTX, cipher: *EVP_CIPHER, engine: *void, key: *u8, iv: *u8) -> s32 #foreign libcrypto;
EVP_DecryptUpdate :: (ctx: *EVP_CIPHER_CTX, out: *u8, outl: *s32, in: *u8, inl: s32) -> s32 #foreign libcrypto;
EVP_DecryptFinal_ex :: (ctx: *EVP_CIPHER_CTX, outm: *u8, outl: *s32) -> s32 #foreign libcrypto;

aes128_gcm_ctx_init :: (key: []u8, iv: []u8) -> *EVP_CIPHER_CTX {
  print("enc key %\n", key);
  print("nonce %\n", iv); 
  ctx := EVP_CIPHER_CTX_new(); assert(ctx != null);

  assert(EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), null, temp_c_string(xx key), temp_c_string(xx iv)) > 0);
  assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, null) > 0);

  return ctx;
}
aes128_gcm_add_associated_data :: (ctx: *EVP_CIPHER_CTX, in: []u8) {
  print("additional %\n", in);
  outlen: s32 = 0;
  assert(EVP_EncryptUpdate(ctx, null, *outlen, in.data, xx in.count) > 0);
  assert(outlen > 0);
}
aes128_gcm_encrypt :: (ctx: *EVP_CIPHER_CTX, in: []u8) -> []u8 {
  outlen: s32 = 0;
  out: []u8 = xx alloc_string(in.count);
  assert(EVP_EncryptUpdate(ctx, out.data, *outlen, in.data, xx in.count) > 0);
  assert(outlen > 0);
  return array_view(out, 0, outlen);
}

aes128_gcm_encrypt_finish :: (ctx: *EVP_CIPHER_CTX) -> data: []u8, tag: [AES_GCM_TAG_SIZE]u8 {
  outlen: s32 = 0;
  // @leak
  // @todo make the api better bru 
  data: []u8 = xx alloc_string(16);
  assert(EVP_EncryptFinal_ex(ctx, data.data, *outlen) > 0);

  tag: [AES_GCM_TAG_SIZE]u8;
  assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, xx tag.count, tag.data) > 0);
  return array_view(data, 0, outlen), tag;
}


evp_digest_sign_init :: (key: *EVP_PKEY) -> *EVP_MD_CTX {
  ctx := EVP_MD_CTX_new(); assert(ctx != null);
  assert(EVP_DigestSignInit(ctx, null, EVP_sha256(), null, key) > 0);
  return ctx;
}

evp_digest_sign_update :: (ctx: *EVP_MD_CTX, data: []u8) -> s32 {
  return EVP_DigestSignUpdate(ctx, data.data, xx data.count);
}

evp_digest_sign_final :: (ctx: *EVP_MD_CTX, sig: []u8 = .[]) -> int {
  siglen: s32 = xx sig.count;
  assert(EVP_DigestSignFinal(ctx, sig.data, *siglen) > 0);
  return siglen;
}

// @todo this should take the curve as parameter
evp_key_deserialize :: (buf: []u8) -> *EVP_PKEY {
  as_key := EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, null, buf.data, buf.count); assert(as_key != null);
  return as_key;
}

evp_key_serialize_public_key :: (k: *EVP_PKEY) -> []u8 {
  len: s32 = 0;
  assert(EVP_PKEY_get_raw_public_key(k, null, *len) == 1);
  assert(len == 32);

  as_str := alloc_string(len);
  assert(EVP_PKEY_get_raw_public_key(k, as_str.data, *len) == 1);
  return xx as_str;
}

generate_ephemeral_ec_key :: () -> *EVP_PKEY {
  pctx := EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, null);
  assert(pctx != null);

  assert(EVP_PKEY_keygen_init(pctx) > 0);

  pkey: *EVP_PKEY;
  assert(EVP_PKEY_keygen(pctx, *pkey) > 0);

  EVP_PKEY_CTX_free(pctx);
  return pkey;
}

derive_shared_secret_key :: (priv: *EVP_PKEY, peer: *EVP_PKEY) -> []u8 {
  ctx := EVP_PKEY_CTX_new(priv, null);
  assert(ctx != null);

  assert(EVP_PKEY_derive_init(ctx) > 0);
  assert(EVP_PKEY_derive_set_peer(ctx, peer) > 0);

  secret_len: u64;
  assert(EVP_PKEY_derive(ctx, null, *secret_len) > 0);

  secret := alloc_string(xx secret_len);

  assert(secret.data != null);
  assert(EVP_PKEY_derive(ctx, secret.data, *secret_len) > 0);

  assert(secret.count == xx secret_len);

  secret.count = xx secret_len;

  EVP_PKEY_CTX_free(ctx);
  return xx secret;
}


sha256_init :: () -> SHA256_CTX {
  ctx: SHA256_CTX;
  if SHA256_Init(*ctx) != 1 assert(false, "SHA256_Init failed"); 
  return ctx;
}

sha256_update :: (ctx: *SHA256_CTX, data: []u8) {
  assert(data.data != null);
  assert(SHA256_Update(ctx, data.data, xx data.count) == 1,  "SHA256_Update failed");
}

sha256_final :: (ctx: *SHA256_CTX) -> [SHA256_DIGEST_LENGTH]u8 {
  ret: [SHA256_DIGEST_LENGTH]u8;
  assert(SHA256_Final(ret.data, ctx) == 1, "SHA256_Final failed");
  return ret;
}

sha256 :: (data: []u8) -> [SHA256_HASH_LENGTH]u8 {
  ret: [SHA256_HASH_LENGTH]u8;
  assert(data.data != null);
  assert(data.count > 0);
  assert(ret.data != null);
  SHA256(data.data, xx data.count, ret.data);
  return ret;
}


hmac_sha256 :: (key: string, msg: string) -> string {
  digest: string;
  digest.data = xx HMAC(EVP_sha256(), key.data, xx key.count, msg.data, xx msg.count, null, null);
  digest.count = 32;
  return digest;
}

// @leak
hmac_sha1 :: (key: string, msg: string) -> string {
  digest: string;
  digest.data = xx HMAC(EVP_sha1(), key.data, xx key.count, msg.data, xx msg.count, null, null);
  digest.count = 20;
  return digest;
}

SSL_error_string :: inline () -> string {
  return to_string(ERR_error_string(ERR_get_error(), null));
}

OpenSSL_add_all_algorithms :: inline () -> s32 {
  return OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
  | OPENSSL_INIT_ADD_ALL_DIGESTS
  | OPENSSL_INIT_LOAD_CONFIG, null);
}

SSL_load_error_strings :: inline () -> s32 {
  return OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS
  | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, null);
}

#scope_file
#import "Basic";
#import "Socket";
#import "POSIX";
#import "utils";
