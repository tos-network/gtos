#include "at/crypto/at_elgamal.h"
#include "at/crypto/at_uno_proofs.h"
#include <stdio.h>

int
at_elgamal_ct_decompress( at_elgamal_ct_t * out,
                          uchar const      in[64] ) {
  if( !out || !in ) return -1;
  if( !at_ristretto255_point_frombytes( &out->commitment, in ) ) return -1;
  if( !at_ristretto255_point_frombytes( &out->handle, in + 32 ) ) return -1;
  return 0;
}

int
at_elgamal_ct_new( at_elgamal_ct_t * out,
                   uchar const       commitment[32],
                   uchar const       handle[32] ) {
  if( !out || !commitment || !handle ) return -1;
  if( !at_ristretto255_point_frombytes( &out->commitment, commitment ) ) return -1;
  if( !at_ristretto255_point_frombytes( &out->handle, handle ) ) return -1;
  return 0;
}

void
at_elgamal_ct_compress( uchar out[64],
                        at_elgamal_ct_t const * in ) {
  if( !out || !in ) return;
  at_ristretto255_point_tobytes( out, &in->commitment );
  at_ristretto255_point_tobytes( out + 32, &in->handle );
}

void
at_elgamal_ct_add( at_elgamal_ct_t *       out,
                   at_elgamal_ct_t const * a,
                   at_elgamal_ct_t const * b ) {
  if( !out || !a || !b ) return;
  at_ristretto255_point_add( &out->commitment, &a->commitment, &b->commitment );
  at_ristretto255_point_add( &out->handle, &a->handle, &b->handle );
}

void
at_elgamal_ct_sub( at_elgamal_ct_t *       out,
                   at_elgamal_ct_t const * a,
                   at_elgamal_ct_t const * b ) {
  if( !out || !a || !b ) return;
  at_ristretto255_point_sub( &out->commitment, &a->commitment, &b->commitment );
  at_ristretto255_point_sub( &out->handle, &a->handle, &b->handle );
}

void
at_elgamal_ct_set_zero( at_elgamal_ct_t * out ) {
  if( !out ) return;
  at_ristretto255_point_set_zero( &out->commitment );
  at_ristretto255_point_set_zero( &out->handle );
}

int
at_elgamal_ct_add_amount( at_elgamal_ct_t *       out,
                          at_elgamal_ct_t const * in,
                          ulong                    amount ) {
  if( !out || !in ) return -1;

  at_ristretto255_point_t g_point[1];
  if( !at_ristretto255_point_frombytes( g_point, AT_RISTRETTO_BASEPOINT_COMPRESSED ) ) return -1;

  uchar amount_scalar[32];
  at_memset( amount_scalar, 0, sizeof(amount_scalar) );
  for( int i=0; i<8; i++ ) amount_scalar[i] = (uchar)(amount >> (8*i));

  at_ristretto255_point_t amount_g[1];
  at_ristretto255_scalar_mul( amount_g, amount_scalar, g_point );
  at_ristretto255_point_add( &out->commitment, &in->commitment, amount_g );
  at_ristretto255_point_set( &out->handle, &in->handle );
  return 0;
}

int
at_elgamal_ct_sub_amount( at_elgamal_ct_t *       out,
                          at_elgamal_ct_t const * in,
                          ulong                    amount ) {
  if( !out || !in ) return -1;

  at_ristretto255_point_t g_point[1];
  if( !at_ristretto255_point_frombytes( g_point, AT_RISTRETTO_BASEPOINT_COMPRESSED ) ) return -1;

  uchar amount_scalar[32];
  at_memset( amount_scalar, 0, sizeof(amount_scalar) );
  for( int i=0; i<8; i++ ) amount_scalar[i] = (uchar)(amount >> (8*i));

  at_ristretto255_point_t amount_g[1];
  at_ristretto255_scalar_mul( amount_g, amount_scalar, g_point );
  at_ristretto255_point_sub( &out->commitment, &in->commitment, amount_g );
  at_ristretto255_point_set( &out->handle, &in->handle );
  return 0;
}

int
at_elgamal_ct_add_scalar( at_elgamal_ct_t *       out,
                          at_elgamal_ct_t const * in,
                          uchar const              scalar[32] ) {
  if( !out || !in || !scalar ) return -1;
  if( !at_curve25519_scalar_validate( scalar ) ) return -1;

  at_ristretto255_point_t g_point[1];
  if( !at_ristretto255_point_frombytes( g_point, AT_RISTRETTO_BASEPOINT_COMPRESSED ) ) return -1;

  at_ristretto255_point_t scalar_g[1];
  at_ristretto255_scalar_mul( scalar_g, scalar, g_point );
  at_ristretto255_point_add( &out->commitment, &in->commitment, scalar_g );
  at_ristretto255_point_set( &out->handle, &in->handle );
  return 0;
}

int
at_elgamal_ct_sub_scalar( at_elgamal_ct_t *       out,
                          at_elgamal_ct_t const * in,
                          uchar const              scalar[32] ) {
  if( !out || !in || !scalar ) return -1;
  if( !at_curve25519_scalar_validate( scalar ) ) return -1;

  at_ristretto255_point_t g_point[1];
  if( !at_ristretto255_point_frombytes( g_point, AT_RISTRETTO_BASEPOINT_COMPRESSED ) ) return -1;

  at_ristretto255_point_t scalar_g[1];
  at_ristretto255_scalar_mul( scalar_g, scalar, g_point );
  at_ristretto255_point_sub( &out->commitment, &in->commitment, scalar_g );
  at_ristretto255_point_set( &out->handle, &in->handle );
  return 0;
}

int
at_elgamal_ct_mul_scalar( at_elgamal_ct_t *       out,
                          at_elgamal_ct_t const * in,
                          uchar const              scalar[32] ) {
  if( !out || !in || !scalar ) return -1;
  if( !at_curve25519_scalar_validate( scalar ) ) return -1;
  at_ristretto255_scalar_mul( &out->commitment, scalar, &in->commitment );
  at_ristretto255_scalar_mul( &out->handle, scalar, &in->handle );
  return 0;
}

int
at_elgamal_ct_add_compressed( uchar out[64],
                              uchar const a[64],
                              uchar const b[64] ) {
  at_elgamal_ct_t ca;
  at_elgamal_ct_t cb;
  at_elgamal_ct_t co;
  if( at_elgamal_ct_decompress( &ca, a ) ) return -1;
  if( at_elgamal_ct_decompress( &cb, b ) ) return -1;
  at_elgamal_ct_add( &co, &ca, &cb );
  at_elgamal_ct_compress( out, &co );
  return 0;
}

int
at_elgamal_ct_sub_compressed( uchar out[64],
                              uchar const a[64],
                              uchar const b[64] ) {
  at_elgamal_ct_t ca;
  at_elgamal_ct_t cb;
  at_elgamal_ct_t co;
  if( at_elgamal_ct_decompress( &ca, a ) ) return -1;
  if( at_elgamal_ct_decompress( &cb, b ) ) return -1;
  at_elgamal_ct_sub( &co, &ca, &cb );
  at_elgamal_ct_compress( out, &co );
  return 0;
}

static int
scalar_is_zero( uchar const s[32] ) {
  uchar acc = 0;
  for( int i=0; i<32; i++ ) acc |= s[i];
  return acc==0;
}

static int
fill_random_bytes( uchar * out,
                   ulong   sz ) {
  FILE * urandom = fopen( "/dev/urandom", "r" );
  if( !urandom ) return -1;
  ulong n = (ulong)fread( out, 1, (size_t)sz, urandom );
  fclose( urandom );
  return n==sz ? 0 : -1;
}

int
at_pedersen_opening_generate( at_pedersen_opening_t * out ) {
  if( !out ) return -1;

  uchar wide[64];
  for( int attempt=0; attempt<8; attempt++ ) {
    if( fill_random_bytes( wide, sizeof(wide) ) ) return -1;
    at_curve25519_scalar_reduce( out->bytes, wide );
    if( !scalar_is_zero( out->bytes ) ) return 0;
  }

  return -1;
}

int
at_pedersen_commitment_new_with_opening( at_elgamal_compressed_commitment_t * out,
                                          ulong                                 amount,
                                          at_pedersen_opening_t const *         opening ) {
  if( !out || !opening ) return -1;
  if( !at_curve25519_scalar_validate( opening->bytes ) ) return -1;

  at_ristretto255_point_t g_point[1];
  at_ristretto255_point_t h_point[1];
  if( !at_ristretto255_point_frombytes( g_point, AT_RISTRETTO_BASEPOINT_COMPRESSED ) ) return -1;
  if( !at_ristretto255_point_frombytes( h_point, AT_PEDERSEN_H_COMPRESSED ) ) return -1;

  uchar amount_scalar[32];
  at_memset( amount_scalar, 0, sizeof(amount_scalar) );
  for( int i=0; i<8; i++ ) amount_scalar[i] = (uchar)(amount >> (8*i));

  at_ristretto255_point_t amount_g[1];
  at_ristretto255_point_t opening_h[1];
  at_ristretto255_point_t commitment[1];
  at_ristretto255_scalar_mul( amount_g, amount_scalar, g_point );
  at_ristretto255_scalar_mul( opening_h, opening->bytes, h_point );
  at_ristretto255_point_add( commitment, amount_g, opening_h );
  at_ristretto255_point_tobytes( out->bytes, commitment );

  return 0;
}

int
at_pedersen_commitment_new( at_elgamal_compressed_commitment_t * out,
                            at_pedersen_opening_t *              opening_out,
                            ulong                                 amount ) {
  if( !out ) return -1;
  at_pedersen_opening_t opening[1];
  if( at_pedersen_opening_generate( opening ) ) return -1;
  if( opening_out ) *opening_out = *opening;
  return at_pedersen_commitment_new_with_opening( out, amount, opening );
}

int
at_elgamal_public_key_from_private( at_elgamal_public_key_t * out,
                                    at_elgamal_private_key_t const * priv ) {
  if( !out || !priv ) return -1;
  if( !at_curve25519_scalar_validate( priv->bytes ) ) return -1;
  if( scalar_is_zero( priv->bytes ) ) return -1;

  at_ristretto255_point_t h_point[1];
  if( !at_ristretto255_point_frombytes( h_point, AT_PEDERSEN_H_COMPRESSED ) ) return -1;

  uchar inv[32];
  at_curve25519_scalar_inv( inv, priv->bytes );

  at_ristretto255_point_t pk[1];
  at_ristretto255_scalar_mul( pk, inv, h_point );
  at_ristretto255_point_tobytes( out->bytes, pk );
  return 0;
}

int
at_elgamal_keypair_generate( at_elgamal_keypair_t * out ) {
  if( !out ) return -1;
  at_pedersen_opening_t opening;
  if( at_pedersen_opening_generate( &opening ) ) return -1;
  at_memcpy( out->private_key.bytes, opening.bytes, 32 );
  return at_elgamal_public_key_from_private( &out->public_key, &out->private_key );
}

int
at_elgamal_decrypt_handle( at_elgamal_compressed_handle_t * out,
                           at_elgamal_public_key_t const *  public_key,
                           at_pedersen_opening_t const *    opening ) {
  if( !out || !public_key || !opening ) return -1;
  if( !at_curve25519_scalar_validate( opening->bytes ) ) return -1;

  at_ristretto255_point_t pk[1];
  if( !at_ristretto255_point_frombytes( pk, public_key->bytes ) ) return -1;

  at_ristretto255_point_t handle[1];
  at_ristretto255_scalar_mul( handle, opening->bytes, pk );
  at_ristretto255_point_tobytes( out->bytes, handle );
  return 0;
}

int
at_elgamal_encrypt_with_opening( at_elgamal_compressed_ciphertext_t * out,
                                 at_elgamal_public_key_t const *       public_key,
                                 ulong                                  amount,
                                 at_pedersen_opening_t const *          opening ) {
  if( !out || !public_key || !opening ) return -1;

  at_elgamal_compressed_commitment_t commitment;
  at_elgamal_compressed_handle_t handle;

  if( at_pedersen_commitment_new_with_opening( &commitment, amount, opening ) ) return -1;
  if( at_elgamal_decrypt_handle( &handle, public_key, opening ) ) return -1;

  at_memcpy( out->bytes,      commitment.bytes, 32 );
  at_memcpy( out->bytes + 32, handle.bytes,     32 );
  return 0;
}

int
at_elgamal_encrypt( at_elgamal_compressed_ciphertext_t * out,
                    at_pedersen_opening_t *              opening_out,
                    at_elgamal_public_key_t const *      public_key,
                    ulong                                 amount ) {
  if( !out || !public_key ) return -1;

  at_pedersen_opening_t opening[1];
  if( at_pedersen_opening_generate( opening ) ) return -1;

  if( at_elgamal_encrypt_with_opening( out, public_key, amount, opening ) ) return -1;

  if( opening_out ) *opening_out = *opening;
  return 0;
}

int
at_elgamal_private_key_decrypt_to_point( uchar                                    out_point[32],
                                         at_elgamal_private_key_t const *         private_key,
                                         at_elgamal_compressed_ciphertext_t const * ciphertext ) {
  if( !out_point || !private_key || !ciphertext ) return -1;
  if( !at_curve25519_scalar_validate( private_key->bytes ) ) return -1;
  if( scalar_is_zero( private_key->bytes ) ) return -1;

  at_elgamal_ct_t ct;
  if( at_elgamal_ct_decompress( &ct, ciphertext->bytes ) ) return -1;

  at_ristretto255_point_t secret_handle[1];
  at_ristretto255_point_t msg_point[1];
  at_ristretto255_scalar_mul( secret_handle, private_key->bytes, &ct.handle );
  at_ristretto255_point_sub( msg_point, &ct.commitment, secret_handle );
  at_ristretto255_point_tobytes( out_point, msg_point );
  return 0;
}

int
at_elgamal_keypair_sign( at_schnorr_signature_t *      signature,
                         at_elgamal_keypair_t const *  keypair,
                         void const *                  message,
                         ulong                         message_sz ) {
  if( !signature || !keypair ) return -1;
  return at_schnorr_sign( signature,
                          keypair->private_key.bytes,
                          keypair->public_key.bytes,
                          message,
                          message_sz ) ? 0 : -1;
}

int
at_elgamal_signature_verify( at_schnorr_signature_t const * signature,
                             at_elgamal_public_key_t const * public_key,
                             void const *                    message,
                             ulong                           message_sz ) {
  if( !signature || !public_key ) return -1;
  return at_schnorr_verify( signature, public_key->bytes, message, message_sz ) ? 0 : -1;
}

int
at_elgamal_public_key_to_address( char *                          out,
                                  ulong                           out_sz,
                                  int                             mainnet,
                                  at_elgamal_public_key_t const * public_key ) {
  if( !out || !public_key ) return -1;
  int rc = at_bech32_address_encode( out, out_sz, mainnet ? 1 : 0, public_key->bytes );
  return rc >= 0 ? 0 : -1;
}
