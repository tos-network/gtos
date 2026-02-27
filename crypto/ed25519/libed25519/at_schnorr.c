/* at_schnorr.c - TOS Schnorr-variant signature implementation

   This implements TOS's custom Schnorr signature scheme using:
   - Ristretto255 (via at_ristretto255.h)
   - SHA3-512 (via at_sha3.h)
   - Pedersen blinding generator H from bulletproofs

   Algorithm details:
   - Public key: PK = priv^(-1) * H
   - Sign: e = SHA3-512(PK || msg || r), s = priv^(-1) * e + k, where r = k * H
   - Verify: r = s*H - e*PK, check e == SHA3-512(PK || msg || r) */

#include "at/crypto/at_schnorr.h"
#include "at/crypto/at_sha3.h"
#include <string.h>
#include <stdio.h>

/* Decompress the H generator point. This is done once per operation.
   Returns 1 on success, 0 on failure. */
static int
at_schnorr_decompress_h( at_ristretto255_point_t * h ) {
  return !!at_ristretto255_point_frombytes( h, at_schnorr_h_generator );
}

/* hash_and_point_to_scalar computes:
   e = SHA3-512(pubkey || message || point) mod L

   This matches TOS's hash_and_point_to_scalar function. */
static void
at_schnorr_hash_to_scalar( uchar             e[ 32 ],
                           uchar const       pubkey[ 32 ],
                           void const *      message,
                           ulong             message_sz,
                           uchar const       point[ 32 ] ) {
  at_sha3_512_t sha[ 1 ];
  uchar hash[ 64 ];

  at_sha3_512_init( sha );
  at_sha3_512_append( sha, pubkey, 32 );
  at_sha3_512_append( sha, message, message_sz );
  at_sha3_512_append( sha, point, 32 );
  at_sha3_512_fini( sha, hash );

  /* Reduce the 64-byte hash to a scalar mod L */
  at_curve25519_scalar_reduce( e, hash );
}

uchar *
at_schnorr_public_key_from_private( uchar       public_key[ 32 ],
                                    uchar const private_key[ 32 ] ) {
  /* Validate private key is a valid non-zero scalar */
  if( !at_curve25519_scalar_validate( private_key ) ) {
    return NULL;
  }

  /* Check private key is not zero */
  int is_zero = 1;
  for( int i = 0; i < 32; i++ ) {
    if( private_key[ i ] != 0 ) {
      is_zero = 0;
      break;
    }
  }
  if( is_zero ) {
    return NULL;
  }

  /* Decompress H generator */
  at_ristretto255_point_t h[ 1 ];
  if( !at_schnorr_decompress_h( h ) ) {
    return NULL;
  }

  /* Compute priv^(-1) */
  uchar priv_inv[ 32 ];
  at_curve25519_scalar_inv( priv_inv, private_key );

  /* Compute PK = priv^(-1) * H */
  at_ristretto255_point_t pk[ 1 ];
  at_ristretto255_scalar_mul( pk, priv_inv, h );

  /* Compress to output */
  at_ristretto255_point_tobytes( public_key, pk );

  return public_key;
}

at_schnorr_signature_t *
at_schnorr_sign_deterministic( at_schnorr_signature_t * signature,
                               uchar const              private_key[ 32 ],
                               uchar const              public_key[ 32 ],
                               void const *             message,
                               ulong                    message_sz,
                               uchar const              k[ 32 ] ) {
  /* Validate inputs */
  if( !at_curve25519_scalar_validate( private_key ) ) return NULL;
  if( !at_curve25519_scalar_validate( k ) ) return NULL;
  if( !at_ristretto255_point_validate( public_key ) ) return NULL;

  /* Decompress H generator */
  at_ristretto255_point_t h[ 1 ];
  if( !at_schnorr_decompress_h( h ) ) {
    return NULL;
  }

  /* Compute r = k * H */
  at_ristretto255_point_t r_point[ 1 ];
  at_ristretto255_scalar_mul( r_point, k, h );

  /* Compress r for hashing */
  uchar r_compressed[ 32 ];
  at_ristretto255_point_tobytes( r_compressed, r_point );

  /* Compute e = SHA3-512(pubkey || message || r) mod L */
  at_schnorr_hash_to_scalar( signature->e, public_key, message, message_sz, r_compressed );

  /* Compute priv^(-1) */
  uchar priv_inv[ 32 ];
  at_curve25519_scalar_inv( priv_inv, private_key );

  /* Compute s = priv^(-1) * e + k */
  uchar priv_inv_e[ 32 ];
  at_curve25519_scalar_mul( priv_inv_e, priv_inv, signature->e );
  at_curve25519_scalar_add( signature->s, priv_inv_e, k );

  return signature;
}

at_schnorr_signature_t *
at_schnorr_sign( at_schnorr_signature_t * signature,
                 uchar const              private_key[ 32 ],
                 uchar const              public_key[ 32 ],
                 void const *             message,
                 ulong                    message_sz ) {
  /* Generate random nonce k */
  uchar k[ 32 ];

  /* Use the system random source (typically /dev/urandom) */
  FILE * urandom = fopen( "/dev/urandom", "r" );
  if( !urandom ) return NULL;

  if( fread( k, 1, 32, urandom ) != 32 ) {
    fclose( urandom );
    return NULL;
  }
  fclose( urandom );

  /* Reduce k to ensure it's a valid scalar */
  uchar k_wide[ 64 ];
  at_memset( k_wide, 0, 64 );
  at_memcpy( k_wide, k, 32 );
  at_curve25519_scalar_reduce( k, k_wide );

  /* Ensure k is not zero (astronomically unlikely but check anyway) */
  int is_zero = 1;
  for( int i = 0; i < 32; i++ ) {
    if( k[ i ] != 0 ) {
      is_zero = 0;
      break;
    }
  }
  if( is_zero ) {
    return NULL;
  }

  return at_schnorr_sign_deterministic( signature, private_key, public_key,
                                        message, message_sz, k );
}

int
at_schnorr_verify( at_schnorr_signature_t const * signature,
                   uchar const                    public_key[ 32 ],
                   void const *                   message,
                   ulong                          message_sz ) {
  /* Validate inputs */
  if( !at_curve25519_scalar_validate( signature->s ) ) return 0;
  if( !at_curve25519_scalar_validate( signature->e ) ) return 0;

  /* Decompress public key */
  at_ristretto255_point_t pk[ 1 ];
  if( !at_ristretto255_point_frombytes( pk, public_key ) ) {
    return 0;
  }

  /* Decompress H generator */
  at_ristretto255_point_t h[ 1 ];
  if( !at_schnorr_decompress_h( h ) ) {
    return 0;
  }

  /* Compute r = s*H - e*PK using multi-scalar multiplication
     r = s*H + (-e)*PK */

  /* First compute -e */
  uchar neg_e[ 32 ];
  at_curve25519_scalar_neg( neg_e, signature->e );

  /* Set up scalars: [s, -e] */
  uchar scalars[ 64 ];
  at_memcpy( scalars,      signature->s, 32 );
  at_memcpy( scalars + 32, neg_e,        32 );

  /* Set up points: [H, PK] */
  at_ristretto255_point_t points[ 2 ];
  at_ristretto255_point_set( &points[ 0 ], h );
  at_ristretto255_point_set( &points[ 1 ], pk );

  /* Compute r = s*H + (-e)*PK */
  at_ristretto255_point_t r_point[ 1 ];
  at_ristretto255_multi_scalar_mul( r_point, scalars, points, 2 );

  /* Compress r */
  uchar r_compressed[ 32 ];
  at_ristretto255_point_tobytes( r_compressed, r_point );

  /* Compute e' = SHA3-512(pubkey || message || r) mod L */
  uchar e_prime[ 32 ];
  at_schnorr_hash_to_scalar( e_prime, public_key, message, message_sz, r_compressed );

  /* Compare e == e' (constant time comparison) */
  int eq = 1;
  for( int i = 0; i < 32; i++ ) {
    eq &= (signature->e[ i ] == e_prime[ i ]);
  }

  return eq;
}

/* Maximum batch size for batch verification.
   For larger batches, we fall back to sequential verification. */
#define SCHNORR_BATCH_MAX 256

int
at_schnorr_verify_batch( at_schnorr_signature_t const * sigs,
                         uchar const                  * pks,      /* n * 32 bytes */
                         void const * const           * msgs,
                         ulong const                  * msg_lens,
                         ulong                          n ) {
  /* Handle edge cases */
  if( n == 0 ) {
    return 1; /* Vacuously true */
  }

  /* TOS Schnorr variant requires computing R = s*H - e*PK and then
     hashing to get e' = H(PK || msg || R), checking e == e'.

     Unlike standard Schnorr (where R is in the signature), we must
     compute R from (s, e) for each signature before we can verify.
     This means we can't easily batch the verification equation.

     However, we can still benefit from:
     1. Decomposing H generator only once
     2. Using efficient MSM for the R computation if we have many
        signatures with the same public key

     For now, we verify each signature sequentially but share the
     H generator decompression. Future optimization: if the same PK
     appears multiple times, we could batch those verifications.

     The Straus MSM implementation is still valuable for other use
     cases like range proof verification where true batching applies. */

  /* Decompress H generator once (shared across all verifications) */
  at_ristretto255_point_t h[ 1 ];
  if( !at_schnorr_decompress_h( h ) ) {
    return 0;
  }

  /* Verify each signature */
  for( ulong i = 0; i < n; i++ ) {
    /* Validate inputs */
    if( !at_curve25519_scalar_validate( sigs[i].s ) ) return 0;
    if( !at_curve25519_scalar_validate( sigs[i].e ) ) return 0;

    /* Decompress public key */
    at_ristretto255_point_t pk[ 1 ];
    if( !at_ristretto255_point_frombytes( pk, &pks[i*32] ) ) {
      return 0;
    }

    /* Compute R = s*H - e*PK = s*H + (-e)*PK */
    uchar neg_e[ 32 ];
    at_curve25519_scalar_neg( neg_e, sigs[i].e );

    uchar verify_scalars[ 64 ];
    at_memcpy( verify_scalars,      sigs[i].s, 32 );
    at_memcpy( verify_scalars + 32, neg_e,     32 );

    at_ristretto255_point_t verify_points[ 2 ];
    at_ristretto255_point_set( &verify_points[0], h );
    at_ristretto255_point_set( &verify_points[1], pk );

    at_ristretto255_point_t r_point[ 1 ];
    at_ristretto255_multi_scalar_mul( r_point, verify_scalars, verify_points, 2 );

    /* Compress R for hashing */
    uchar r_compressed[ 32 ];
    at_ristretto255_point_tobytes( r_compressed, r_point );

    /* Compute e' = SHA3-512(PK || msg || R) mod L */
    uchar e_prime[ 32 ];
    at_schnorr_hash_to_scalar( e_prime, &pks[i*32], msgs[i], msg_lens[i], r_compressed );

    /* Check if e matches e' (constant time comparison) */
    int e_matches = 1;
    for( int j = 0; j < 32; j++ ) {
      e_matches &= (sigs[i].e[j] == e_prime[j]);
    }

    if( !e_matches ) {
      return 0; /* This signature is invalid */
    }
  }

  /* All signatures verified successfully */
  return 1;
}