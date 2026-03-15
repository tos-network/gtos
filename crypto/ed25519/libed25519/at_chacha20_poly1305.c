/* at_chacha20_poly1305.c - ChaCha20-Poly1305 AEAD (RFC 8439)

   This implementation follows RFC 8439 Section 2.8 for the AEAD construction.
*/

#include "at/crypto/at_chacha20_poly1305.h"
#include <string.h>

/**********************************************************************/
/* Internal Helpers                                                   */
/**********************************************************************/

/* Store 64-bit little-endian value */
static inline void
store64_le( uchar * p, ulong v ) {
  p[0] = (uchar)(v >>  0);
  p[1] = (uchar)(v >>  8);
  p[2] = (uchar)(v >> 16);
  p[3] = (uchar)(v >> 24);
  p[4] = (uchar)(v >> 32);
  p[5] = (uchar)(v >> 40);
  p[6] = (uchar)(v >> 48);
  p[7] = (uchar)(v >> 56);
}

/* Constant-time memory comparison */
static int
ct_memcmp( uchar const * a, uchar const * b, ulong len ) {
  uint diff = 0;
  for( ulong i = 0; i < len; i++ ) {
    diff |= a[i] ^ b[i];
  }
  return (diff == 0) ? 0 : 1;
}

/* Pad length to 16 bytes (returns number of zero bytes to add) */
static inline ulong
pad16( ulong len ) {
  return (16 - (len & 15)) & 15;
}

/**********************************************************************/
/* Core AEAD Construction                                             */
/**********************************************************************/

/* Generate Poly1305 key using ChaCha20 (RFC 8439 Section 2.6) */
static void
generate_poly1305_key( uchar         poly_key[32],
                       uchar const   key[32],
                       uchar const   nonce[12] ) {
  at_chacha20_ctx_t ctx;

  /* Use counter = 0 to generate the Poly1305 key */
  at_chacha20_init( &ctx, key, nonce, 0 );

  /* First 32 bytes of keystream become the Poly1305 key */
  at_chacha20_keystream( &ctx, poly_key, 32 );

  /* Clear context */
  at_memset( &ctx, 0, sizeof(ctx) );
}

/* Compute Poly1305 tag over AAD and ciphertext per RFC 8439 */
static void
compute_tag( uchar               tag[16],
             uchar const         poly_key[32],
             uchar const *       aad,
             ulong               aad_len,
             uchar const *       ciphertext,
             ulong               ciphertext_len ) {
  at_poly1305_ctx_t poly_ctx;
  uchar zeros[16] = {0};
  uchar len_block[16];

  at_poly1305_init( &poly_ctx, poly_key );

  /* Process AAD */
  if( aad_len > 0 ) {
    at_poly1305_update( &poly_ctx, aad, aad_len );
  }

  /* Pad AAD to 16-byte boundary */
  ulong aad_pad = pad16( aad_len );
  if( aad_pad > 0 ) {
    at_poly1305_update( &poly_ctx, zeros, aad_pad );
  }

  /* Process ciphertext */
  if( ciphertext_len > 0 ) {
    at_poly1305_update( &poly_ctx, ciphertext, ciphertext_len );
  }

  /* Pad ciphertext to 16-byte boundary */
  ulong ct_pad = pad16( ciphertext_len );
  if( ct_pad > 0 ) {
    at_poly1305_update( &poly_ctx, zeros, ct_pad );
  }

  /* Append lengths as 64-bit little-endian */
  store64_le( len_block + 0, aad_len );
  store64_le( len_block + 8, ciphertext_len );
  at_poly1305_update( &poly_ctx, len_block, 16 );

  /* Finalize */
  at_poly1305_final( &poly_ctx, tag );
}

/**********************************************************************/
/* Public API                                                         */
/**********************************************************************/

uchar *
at_chacha20_poly1305_encrypt( uchar *       ciphertext,
                              uchar const   key[32],
                              uchar const   nonce[12],
                              uchar const * aad,
                              ulong         aad_len,
                              uchar const * plaintext,
                              ulong         plaintext_len ) {
  uchar poly_key[32];
  at_chacha20_ctx_t chacha_ctx;

  /* Generate one-time Poly1305 key */
  generate_poly1305_key( poly_key, key, nonce );

  /* Encrypt plaintext using ChaCha20 with counter starting at 1 */
  at_chacha20_init( &chacha_ctx, key, nonce, 1 );
  at_chacha20_crypt( &chacha_ctx, ciphertext, plaintext, plaintext_len );

  /* Compute and append authentication tag */
  compute_tag( ciphertext + plaintext_len, poly_key, aad, aad_len,
               ciphertext, plaintext_len );

  /* Clear sensitive data */
  at_memset( poly_key, 0, sizeof(poly_key) );
  at_memset( &chacha_ctx, 0, sizeof(chacha_ctx) );

  return ciphertext;
}

int
at_chacha20_poly1305_decrypt( uchar *       plaintext,
                              uchar const   key[32],
                              uchar const   nonce[12],
                              uchar const * aad,
                              ulong         aad_len,
                              uchar const * ciphertext,
                              ulong         ciphertext_len ) {
  uchar poly_key[32];
  uchar computed_tag[16];
  at_chacha20_ctx_t chacha_ctx;

  /* Validate input */
  if( ciphertext_len < AT_CHACHA20_POLY1305_TAG_SZ ) {
    return AT_CHACHA20_POLY1305_ERR_INVAL;
  }

  ulong ct_len = ciphertext_len - AT_CHACHA20_POLY1305_TAG_SZ;
  uchar const * received_tag = ciphertext + ct_len;

  /* Generate one-time Poly1305 key */
  generate_poly1305_key( poly_key, key, nonce );

  /* Compute expected tag */
  compute_tag( computed_tag, poly_key, aad, aad_len, ciphertext, ct_len );

  /* Verify tag in constant time */
  if( ct_memcmp( computed_tag, received_tag, 16 ) != 0 ) {
    /* Authentication failed - clear output */
    if( plaintext && ct_len > 0 ) {
      at_memset( plaintext, 0, ct_len );
    }
    at_memset( poly_key, 0, sizeof(poly_key) );
    at_memset( computed_tag, 0, sizeof(computed_tag) );
    return AT_CHACHA20_POLY1305_ERR_AUTH;
  }

  /* Decrypt ciphertext using ChaCha20 with counter starting at 1 */
  at_chacha20_init( &chacha_ctx, key, nonce, 1 );
  at_chacha20_crypt( &chacha_ctx, plaintext, ciphertext, ct_len );

  /* Clear sensitive data */
  at_memset( poly_key, 0, sizeof(poly_key) );
  at_memset( computed_tag, 0, sizeof(computed_tag) );
  at_memset( &chacha_ctx, 0, sizeof(chacha_ctx) );

  return AT_CHACHA20_POLY1305_SUCCESS;
}

int
at_chacha20_poly1305_encrypt_in_place( uchar *       buf,
                                       ulong         buf_len,
                                       uchar const   key[32],
                                       uchar const   nonce[12],
                                       uchar const * aad,
                                       ulong         aad_len ) {
  uchar poly_key[32];
  at_chacha20_ctx_t chacha_ctx;

  /* Generate one-time Poly1305 key */
  generate_poly1305_key( poly_key, key, nonce );

  /* Encrypt in place using ChaCha20 with counter starting at 1 */
  at_chacha20_init( &chacha_ctx, key, nonce, 1 );
  at_chacha20_crypt( &chacha_ctx, buf, buf, buf_len );

  /* Compute and append authentication tag */
  compute_tag( buf + buf_len, poly_key, aad, aad_len, buf, buf_len );

  /* Clear sensitive data */
  at_memset( poly_key, 0, sizeof(poly_key) );
  at_memset( &chacha_ctx, 0, sizeof(chacha_ctx) );

  return AT_CHACHA20_POLY1305_SUCCESS;
}

int
at_chacha20_poly1305_decrypt_in_place( uchar *       buf,
                                       ulong         buf_len,
                                       uchar const   key[32],
                                       uchar const   nonce[12],
                                       uchar const * aad,
                                       ulong         aad_len ) {
  uchar poly_key[32];
  uchar computed_tag[16];
  at_chacha20_ctx_t chacha_ctx;

  /* Validate input */
  if( buf_len < AT_CHACHA20_POLY1305_TAG_SZ ) {
    return AT_CHACHA20_POLY1305_ERR_INVAL;
  }

  ulong ct_len = buf_len - AT_CHACHA20_POLY1305_TAG_SZ;
  uchar * received_tag = buf + ct_len;

  /* Generate one-time Poly1305 key */
  generate_poly1305_key( poly_key, key, nonce );

  /* Compute expected tag */
  compute_tag( computed_tag, poly_key, aad, aad_len, buf, ct_len );

  /* Verify tag in constant time */
  if( ct_memcmp( computed_tag, received_tag, 16 ) != 0 ) {
    /* Authentication failed - clear buffer */
    at_memset( buf, 0, buf_len );
    at_memset( poly_key, 0, sizeof(poly_key) );
    at_memset( computed_tag, 0, sizeof(computed_tag) );
    return AT_CHACHA20_POLY1305_ERR_AUTH;
  }

  /* Decrypt in place using ChaCha20 with counter starting at 1 */
  at_chacha20_init( &chacha_ctx, key, nonce, 1 );
  at_chacha20_crypt( &chacha_ctx, buf, buf, ct_len );

  /* Clear sensitive data */
  at_memset( poly_key, 0, sizeof(poly_key) );
  at_memset( computed_tag, 0, sizeof(computed_tag) );
  at_memset( &chacha_ctx, 0, sizeof(chacha_ctx) );

  return AT_CHACHA20_POLY1305_SUCCESS;
}