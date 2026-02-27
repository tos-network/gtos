/* at_rangeproofs_table_bulletproofs.c - Bulletproofs-compatible generator tables

   This table provides generators that are compatible with the Rust bulletproofs crate.
   The generators are stored in compressed form and decompressed at initialization time.

   Usage:
     1. Call at_rangeproofs_init() once at startup (called automatically by at_rangeproofs_verify)
     2. Use at_rangeproofs_basepoint_G, at_rangeproofs_basepoint_H,
        at_rangeproofs_generators_G, at_rangeproofs_generators_H as usual */

#ifndef HEADER_at_ballet_at_rangeproofs_h
#error "Do not include this directly; use at_rangeproofs.h"
#endif

/* Include the compressed generator data */
#include "at_rangeproofs_table_compressed_data.inc"

/* Static storage for decompressed generators - these are the actual definitions
   that match the extern declarations in at_rangeproofs.h */
static at_ristretto255_point_t at_rangeproofs_basepoint_G[1];
static at_ristretto255_point_t at_rangeproofs_basepoint_H[1];
static at_ristretto255_point_t at_rangeproofs_generators_G[256];
static at_ristretto255_point_t at_rangeproofs_generators_H[256];

/* Initialization state */
static int at_rangeproofs_initialized = 0;

/* at_rangeproofs_init decompresses all generators.
   Returns 0 on success, -1 on failure.
   This function is idempotent. */
static int
at_rangeproofs_init( void ) {
  if( at_rangeproofs_initialized ) {
    return 0;  /* Already initialized */
  }

  /* Decompress basepoint G */
  if( at_ristretto255_point_frombytes( at_rangeproofs_basepoint_G,
                                       at_rangeproofs_basepoint_G_compressed ) == NULL ) {
    return -1;
  }

  /* Decompress basepoint H */
  if( at_ristretto255_point_frombytes( at_rangeproofs_basepoint_H,
                                       at_rangeproofs_basepoint_H_compressed ) == NULL ) {
    return -1;
  }

  /* Decompress all G generators */
  for( int i = 0; i < 256; i++ ) {
    if( at_ristretto255_point_frombytes( &at_rangeproofs_generators_G[i],
                                         at_rangeproofs_generators_G_compressed[i] ) == NULL ) {
      return -1;
    }
  }

  /* Decompress all H generators */
  for( int i = 0; i < 256; i++ ) {
    if( at_ristretto255_point_frombytes( &at_rangeproofs_generators_H[i],
                                         at_rangeproofs_generators_H_compressed[i] ) == NULL ) {
      return -1;
    }
  }

  at_rangeproofs_initialized = 1;

  /* Debug: verify G[0] matches expected value */
  /* Expected (bulletproofs crate): fc3b25801422672a6a8d3adb5d8457d4301fe92324b4fc56ae934c8713ddfe2d */
  uchar g0_compressed[32];
  at_ristretto255_point_tobytes( g0_compressed, &at_rangeproofs_generators_G[0] );
  if( g0_compressed[0] != 0xfc || g0_compressed[1] != 0x3b ) {
    /* G[0] doesn't match expected - indicates decompression problem */
    return -2;  /* Different error code for debugging */
  }

  return 0;
}