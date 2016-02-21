#ifdef HAVE_GNUTLS
	#include <gnutls/gnutls.h>
	#include <gnutls/crypto.h>

	#define hash_global_init gnutls_global_init
	#define hash_ctx gnutls_hash_hd_t
	#define hash_alg gnutls_digest_algorithm_t
	#define hash_null 0
	#define hash_getbyname(name) (gnutls_digest_get_id (name))
	#define hash_getsize(name) (gnutls_hash_get_len (name))
	#define hash_init(ctx,md) {gnutls_hash_init (&ctx, md);}
	#define hash_update(ctx,buf,len) (gnutls_hash (ctx, buf, len))
	#define hash_finish(ctx,buf) {gnutls_hash_deinit (ctx, buf);}
	#define hash_global_cleanup gnutls_global_deinit
#else
	#include <openssl/evp.h>

	#define hash_global_init OpenSSL_add_all_digests
	#define hash_ctx EVP_MD_CTX *
	#define hash_alg const EVP_MD *
	#define hash_null NULL
	#define hash_getbyname(name) (EVP_get_digestbyname (name))
	#define hash_getsize(name) (EVP_MD_size (name))
	#define hash_init(ctx,md) {ctx = EVP_MD_CTX_create(); EVP_DigestInit_ex (ctx, md, NULL);}
	#define hash_update(ctx,buf,len) (EVP_DigestUpdate (ctx, buf, len))
	#define hash_finish(ctx,buf) {EVP_DigestFinal_ex (ctx, buf, NULL); EVP_MD_CTX_destroy (ctx);}
	#define hash_global_cleanup EVP_cleanup
#endif
