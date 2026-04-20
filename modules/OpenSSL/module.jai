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

SSL_METHOD      ::  void;
SSL_CTX         ::  void;
SSL             ::  void;
X509_STORE      ::  void;
X509            ::  void;
X509_STORE_CTX  ::  void;
BIO             ::  void;
EVP_PKEY        ::  void;
EVP_MD_CTX      ::  void;
EVP_MD          ::  void;

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
d2i_X509 :: (x: **void, in: **u8, len: s64) -> *X509 #foreign libssl;
X509_STORE_CTX_new :: () -> *X509_STORE_CTX #foreign libssl;
X509_STORE_CTX_init :: (ctx: *X509_STORE_CTX, trust_store: *X509_STORE,
    target: *X509, untrusted: *void) -> s32 #foreign libssl;
X509_verify_cert :: (ctx: *X509_STORE_CTX) -> s32 #foreign libssl;
X509_STORE_CTX_get_error :: (ctx: *X509_STORE_CTX) -> s32 #foreign libssl;
X509_verify_cert_error_string :: (n: s32) -> *u8 #foreign libssl;
X509_free :: (ptr: *X509) #foreign libssl;
SHA256 :: (d: *u8, n: u64, md: *u8) -> *u8 #foreign libssl;

SHA256_HASH_LENGTH :: 32;

sha256 :: (data: []u8) -> [SHA256_HASH_LENGTH]u8 {
  ret: [SHA256_HASH_LENGTH]u8;
  assert(data.data != null);
  assert(data.count > 0);
  assert(ret.data != null);
  SHA256(data.data, xx data.count, ret.data);
  return ret;
}


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
