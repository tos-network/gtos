/* at_chacha.c - ChaCha20 Stream Cipher Implementation (RFC 8439) */

#include "at/crypto/at_chacha.h"
#include "at/infra/at_util.h"
#include <string.h>

/**********************************************************************/
/* Block Function (Core)                                              */
/**********************************************************************/

static inline void
at_chacha_quarter_round( uint * a,
                         uint * b,
                         uint * c,
                         uint * d ) {
  *a += *b; *d ^= *a; *d = at_uint_rotate_left(*d, 16);
  *c += *d; *b ^= *c; *b = at_uint_rotate_left(*b, 12);
  *a += *b; *d ^= *a; *d = at_uint_rotate_left(*d,  8);
  *c += *d; *b ^= *c; *b = at_uint_rotate_left(*b,  7);
}

__attribute__((always_inline)) static inline void *
at_chacha_block( void *       _block,
                 void const * _key,
                 void const * _idx_nonce,
                 ulong        rnd2_cnt ) {

  uint *       block     = __builtin_assume_aligned( _block,     64UL );
  uint const * key       = __builtin_assume_aligned( _key,       32UL );
  uint const * idx_nonce = __builtin_assume_aligned( _idx_nonce, 16UL );

  /* Construct the input ChaCha20 block state as the following
     matrix of little endian uint entries:

     cccccccc  cccccccc  cccccccc  cccccccc
     kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
     kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
     bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

     Where
       c are the constants 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
       k is the input key
       b is the block index
       n is the nonce */

  block[ 0 ] = 0x61707865U;
  block[ 1 ] = 0x3320646eU;
  block[ 2 ] = 0x79622d32U;
  block[ 3 ] = 0x6b206574U;

  at_memcpy( block+ 4, key,       8*sizeof(uint) );
  at_memcpy( block+12, idx_nonce, 4*sizeof(uint) );

  /* Remember the input state for later use */

  uint block_pre[ 16 ] __attribute__((aligned(32)));
  at_memcpy( block_pre, block, 64UL );

  /* Run the ChaCha round function 20 times.
     (Each iteration does a column round and a diagonal round.) */

  for( ulong i=0UL; i<rnd2_cnt; i++ ) {
    at_chacha_quarter_round( &block[ 0 ], &block[ 4 ], &block[  8 ], &block[ 12 ] );
    at_chacha_quarter_round( &block[ 1 ], &block[ 5 ], &block[  9 ], &block[ 13 ] );
    at_chacha_quarter_round( &block[ 2 ], &block[ 6 ], &block[ 10 ], &block[ 14 ] );
    at_chacha_quarter_round( &block[ 3 ], &block[ 7 ], &block[ 11 ], &block[ 15 ] );
    at_chacha_quarter_round( &block[ 0 ], &block[ 5 ], &block[ 10 ], &block[ 15 ] );
    at_chacha_quarter_round( &block[ 1 ], &block[ 6 ], &block[ 11 ], &block[ 12 ] );
    at_chacha_quarter_round( &block[ 2 ], &block[ 7 ], &block[  8 ], &block[ 13 ] );
    at_chacha_quarter_round( &block[ 3 ], &block[ 4 ], &block[  9 ], &block[ 14 ] );
  }

  /* Complete the block by adding the input state */

  for( ulong i=0UL; i<16UL; i++ )
    block[ i ] += block_pre[ i ];

  return (void *)block;
}

void *
at_chacha8_block( void *       _block,
                  void const * _key,
                  void const * _idx_nonce ) {
  return at_chacha_block( _block, _key, _idx_nonce, 4UL );
}

void *
at_chacha20_block( void *       _block,
                   void const * _key,
                   void const * _idx_nonce ) {
  return at_chacha_block( _block, _key, _idx_nonce, 10UL );
}

/**********************************************************************/
/* Stream Cipher                                                      */
/**********************************************************************/

/* Generate a keystream block and advance the counter */
static void
chacha20_block_gen( at_chacha20_ctx_t * ctx ) {
  /* Build idx_nonce: [4-byte counter LE][12-byte nonce] */
  uchar idx_nonce[16] __attribute__((aligned(16)));

  /* Counter in little-endian */
  idx_nonce[0] = (uchar)(ctx->counter >>  0);
  idx_nonce[1] = (uchar)(ctx->counter >>  8);
  idx_nonce[2] = (uchar)(ctx->counter >> 16);
  idx_nonce[3] = (uchar)(ctx->counter >> 24);

  /* Copy nonce */
  at_memcpy( idx_nonce + 4, ctx->nonce, 12 );

  /* Generate block */
  at_chacha20_block( ctx->block, ctx->key, idx_nonce );

  /* Increment counter */
  ctx->counter++;
  ctx->block_offset = 0;
}

void
at_chacha20_init( at_chacha20_ctx_t * ctx,
                  uchar const         key[32],
                  uchar const         nonce[12],
                  uint                counter ) {
  at_memcpy( ctx->key, key, 32 );
  at_memcpy( ctx->nonce, nonce, 12 );
  ctx->counter = counter;
  ctx->block_offset = 64;  /* Force block generation on first use */
}

void *
at_chacha20_crypt( at_chacha20_ctx_t * ctx,
                   void *              out,
                   void const *        in,
                   ulong               len ) {
  uchar *       out_p = (uchar *)out;
  uchar const * in_p  = (uchar const *)in;

  while( len > 0 ) {
    /* Generate new block if needed */
    if( ctx->block_offset >= 64 ) {
      chacha20_block_gen( ctx );
    }

    /* XOR with keystream */
    ulong available = 64 - ctx->block_offset;
    ulong to_process = (len < available) ? len : available;

    for( ulong i = 0; i < to_process; i++ ) {
      out_p[i] = in_p[i] ^ ctx->block[ctx->block_offset + i];
    }

    ctx->block_offset += (uint)to_process;
    out_p += to_process;
    in_p  += to_process;
    len   -= to_process;
  }

  return out;
}

void
at_chacha20_keystream( at_chacha20_ctx_t * ctx,
                       void *              out,
                       ulong               len ) {
  uchar * out_p = (uchar *)out;

  while( len > 0 ) {
    /* Generate new block if needed */
    if( ctx->block_offset >= 64 ) {
      chacha20_block_gen( ctx );
    }

    /* Copy keystream */
    ulong available = 64 - ctx->block_offset;
    ulong to_copy = (len < available) ? len : available;

    at_memcpy( out_p, ctx->block + ctx->block_offset, to_copy );

    ctx->block_offset += (uint)to_copy;
    out_p += to_copy;
    len   -= to_copy;
  }
}