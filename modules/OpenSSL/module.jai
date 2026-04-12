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

SSL_METHOD :: void;
SSL_CTX :: void;
SSL :: void;

TLS_client_method :: () -> *SSL_METHOD #foreign libssl;
SSL_CTX_new :: (meth: *SSL_METHOD) -> *SSL_CTX #foreign libssl;
SSL_new :: (ctx: *SSL_CTX) -> *SSL #foreign libssl;
SSL_set_fd :: (ssl: *SSL, fd: s32) -> s32 #foreign libssl;
SSL_connect :: (ssl: *SSL) -> s32 #foreign libssl;
SSL_write :: (ssl: *SSL, buf: *void, num: s32) -> s32 #foreign libssl;
SSL_read :: (ssl: *SSL, buf: *void, num: s32) -> s32 #foreign libssl;
SSL_get_error :: (ssl: *SSL, ret: s32) -> s32 #foreign libssl;
ERR_error_string :: (ret: s32, buf: *u8) -> *u8 #foreign libssl;
RAND_bytes :: (buf: *u8, num: s32) -> s32 #foreign libcrypto;
EVP_MD :: void;
HMAC :: (evp_md: *EVP_MD, key: *u8, key_len: s32, data: *u8, data_len: u64,
                    md: *u8, md_len: *u32) -> *u8 #foreign libssl;
EVP_sha1 :: () -> *EVP_MD #foreign libssl;


hmac_sha1 :: (key: string, msg: string) -> string {
  digest: string;
  digest.data = xx HMAC(EVP_sha1(), key.data, xx key.count, msg.data, xx msg.count, null, null);
  digest.count = 20;
  return digest;
}
SSL_error_string :: inline (ret: s32) -> string {
  return to_string(ERR_error_string());
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
