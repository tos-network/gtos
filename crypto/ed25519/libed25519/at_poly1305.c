/* at_poly1305.c - Poly1305 Message Authentication Code (RFC 8439)

   Reference implementation using 26-bit limbs in 32-bit integers.
   Not optimized for high performance.
*/

#include "at/crypto/at_poly1305.h"
#include <string.h>

/**********************************************************************/
/* Internal Helpers                                                   */
/**********************************************************************/

/* Load 32-bit little-endian value */
static inline uint
load32_le( uchar const * p ) {
  return ((uint)p[0] <<  0) |
         ((uint)p[1] <<  8) |
         ((uint)p[2] << 16) |
         ((uint)p[3] << 24);
}

/* Store 32-bit little-endian value */
static inline void
store32_le( uchar * p, uint v ) {
  p[0] = (uchar)(v >>  0);
  p[1] = (uchar)(v >>  8);
  p[2] = (uchar)(v >> 16);
  p[3] = (uchar)(v >> 24);
}

/* Clamp r according to RFC 8439 Section 2.5 */
static void
clamp( uchar r[16] ) {
  r[ 3] &= 0x0f;
  r[ 7] &= 0x0f;
  r[11] &= 0x0f;
  r[15] &= 0x0f;
  r[ 4] &= 0xfc;
  r[ 8] &= 0xfc;
  r[12] &= 0xfc;
}

/* Process a 16-byte block */
static void
poly1305_block( at_poly1305_ctx_t * ctx,
                uchar const         block[16],
                uint                hibit ) {
  /* Load block as 5 x 26-bit limbs */
  uint h0 = ctx->h[0];
  uint h1 = ctx->h[1];
  uint h2 = ctx->h[2];
  uint h3 = ctx->h[3];
  uint h4 = ctx->h[4];

  uint r0 = ctx->r[0];
  uint r1 = ctx->r[1];
  uint r2 = ctx->r[2];
  uint r3 = ctx->r[3];
  uint r4 = ctx->r[4];

  /* h += m */
  uint t0 = load32_le( block +  0 );
  uint t1 = load32_le( block +  4 );
  uint t2 = load32_le( block +  8 );
  uint t3 = load32_le( block + 12 );

  h0 += ( t0                     ) & 0x3ffffff;
  h1 += ((t0 >> 26) | (t1 <<  6)) & 0x3ffffff;
  h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
  h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
  h4 += ((t3 >>  8)             ) | (hibit << 24);

  /* h *= r (mod 2^130 - 5) */
  /* Using 64-bit arithmetic for the multiplication */

  uint s1 = r1 * 5;
  uint s2 = r2 * 5;
  uint s3 = r3 * 5;
  uint s4 = r4 * 5;

  ulong d0 = (ulong)h0*r0 + (ulong)h1*s4 + (ulong)h2*s3 + (ulong)h3*s2 + (ulong)h4*s1;
  ulong d1 = (ulong)h0*r1 + (ulong)h1*r0 + (ulong)h2*s4 + (ulong)h3*s3 + (ulong)h4*s2;
  ulong d2 = (ulong)h0*r2 + (ulong)h1*r1 + (ulong)h2*r0 + (ulong)h3*s4 + (ulong)h4*s3;
  ulong d3 = (ulong)h0*r3 + (ulong)h1*r2 + (ulong)h2*r1 + (ulong)h3*r0 + (ulong)h4*s4;
  ulong d4 = (ulong)h0*r4 + (ulong)h1*r3 + (ulong)h2*r2 + (ulong)h3*r1 + (ulong)h4*r0;

  /* Carry propagation */
  ulong c;
  c = d0 >> 26; h0 = (uint)d0 & 0x3ffffff; d1 += c;
  c = d1 >> 26; h1 = (uint)d1 & 0x3ffffff; d2 += c;
  c = d2 >> 26; h2 = (uint)d2 & 0x3ffffff; d3 += c;
  c = d3 >> 26; h3 = (uint)d3 & 0x3ffffff; d4 += c;
  c = d4 >> 26; h4 = (uint)d4 & 0x3ffffff;

  /* Reduce mod 2^130 - 5 */
  h0 += (uint)c * 5;
  c = h0 >> 26; h0 &= 0x3ffffff;
  h1 += (uint)c;

  ctx->h[0] = h0;
  ctx->h[1] = h1;
  ctx->h[2] = h2;
  ctx->h[3] = h3;
  ctx->h[4] = h4;
}

/**********************************************************************/
/* Public API                                                         */
/**********************************************************************/

void
at_poly1305_init( at_poly1305_ctx_t * ctx,
                  uchar const         key[32] ) {
  /* Clamp r (first 16 bytes of key) */
  uchar r[16];
  at_memcpy( r, key, 16 );
  clamp( r );

  /* Load r as 5 x 26-bit limbs */
  uint t0 = load32_le( r +  0 );
  uint t1 = load32_le( r +  4 );
  uint t2 = load32_le( r +  8 );
  uint t3 = load32_le( r + 12 );

  ctx->r[0] = ( t0                     ) & 0x3ffffff;
  ctx->r[1] = ((t0 >> 26) | (t1 <<  6)) & 0x3ffffff;
  ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
  ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
  ctx->r[4] = ((t3 >>  8)             ) & 0x3ffffff;

  /* Load s (last 16 bytes of key) */
  ctx->s[0] = load32_le( key + 16 );
  ctx->s[1] = load32_le( key + 20 );
  ctx->s[2] = load32_le( key + 24 );
  ctx->s[3] = load32_le( key + 28 );

  /* Initialize accumulator to zero */
  ctx->h[0] = 0;
  ctx->h[1] = 0;
  ctx->h[2] = 0;
  ctx->h[3] = 0;
  ctx->h[4] = 0;

  ctx->buf_len = 0;
}

void
at_poly1305_update( at_poly1305_ctx_t * ctx,
                    uchar const *       msg,
                    ulong               msg_len ) {
  /* Handle buffered data */
  if( ctx->buf_len > 0 ) {
    ulong want = 16 - ctx->buf_len;
    if( msg_len < want ) {
      at_memcpy( ctx->buf + ctx->buf_len, msg, msg_len );
      ctx->buf_len += msg_len;
      return;
    }
    at_memcpy( ctx->buf + ctx->buf_len, msg, want );
    poly1305_block( ctx, ctx->buf, 1 );
    msg += want;
    msg_len -= want;
    ctx->buf_len = 0;
  }

  /* Process full blocks */
  while( msg_len >= 16 ) {
    poly1305_block( ctx, msg, 1 );
    msg += 16;
    msg_len -= 16;
  }

  /* Buffer remaining */
  if( msg_len > 0 ) {
    at_memcpy( ctx->buf, msg, msg_len );
    ctx->buf_len = msg_len;
  }
}

void
at_poly1305_final( at_poly1305_ctx_t * ctx,
                   uchar               tag[16] ) {
  /* Process final partial block */
  if( ctx->buf_len > 0 ) {
    ctx->buf[ctx->buf_len] = 1;
    at_memset( ctx->buf + ctx->buf_len + 1, 0, 16 - ctx->buf_len - 1 );
    poly1305_block( ctx, ctx->buf, 0 );
  }

  /* Fully reduce h */
  uint h0 = ctx->h[0];
  uint h1 = ctx->h[1];
  uint h2 = ctx->h[2];
  uint h3 = ctx->h[3];
  uint h4 = ctx->h[4];

  uint c;
  c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
  c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
  c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
  c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
  c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

  /* Compute h - p */
  uint g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
  uint g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
  uint g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
  uint g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
  uint g4 = h4 + c - (1 << 26);

  /* Select h if h < p, else h - p */
  uint mask = (g4 >> 31) - 1;  /* All 1s if g4 >= 0 (h >= p) */
  g0 &= mask;
  g1 &= mask;
  g2 &= mask;
  g3 &= mask;
  g4 &= mask;
  mask = ~mask;
  h0 = (h0 & mask) | g0;
  h1 = (h1 & mask) | g1;
  h2 = (h2 & mask) | g2;
  h3 = (h3 & mask) | g3;
  h4 = (h4 & mask) | g4;

  /* Convert from 5 x 26-bit limbs to 4 x 32-bit words
     h = h0 + h1*2^26 + h2*2^52 + h3*2^78 + h4*2^104 */
  uint t0 = h0 | (h1 << 26);         /* bits 0-31 */
  uint t1 = (h1 >> 6) | (h2 << 20);  /* bits 32-63 */
  uint t2 = (h2 >> 12) | (h3 << 14); /* bits 64-95 */
  uint t3 = (h3 >> 18) | (h4 << 8);  /* bits 96-127 */

  /* Add s with carry propagation */
  ulong f0 = (ulong)t0 + ctx->s[0];
  ulong f1 = (ulong)t1 + ctx->s[1] + (f0 >> 32);
  ulong f2 = (ulong)t2 + ctx->s[2] + (f1 >> 32);
  ulong f3 = (ulong)t3 + ctx->s[3] + (f2 >> 32);

  /* Output tag (lower 128 bits) */
  store32_le( tag +  0, (uint)f0 );
  store32_le( tag +  4, (uint)f1 );
  store32_le( tag +  8, (uint)f2 );
  store32_le( tag + 12, (uint)f3 );

  /* Clear sensitive data */
  at_memset( ctx, 0, sizeof(*ctx) );
}

uchar *
at_poly1305( uchar         tag[16],
             uchar const   key[32],
             uchar const * msg,
             ulong         msg_len ) {
  at_poly1305_ctx_t ctx;
  at_poly1305_init( &ctx, key );
  at_poly1305_update( &ctx, msg, msg_len );
  at_poly1305_final( &ctx, tag );
  return tag;
}

int
at_poly1305_verify( uchar const   expected[16],
                    uchar const   key[32],
                    uchar const * msg,
                    ulong         msg_len ) {
  uchar computed[16];
  at_poly1305( computed, key, msg, msg_len );

  /* Constant-time comparison */
  uint diff = 0;
  for( int i = 0; i < 16; i++ ) {
    diff |= computed[i] ^ expected[i];
  }

  /* Clear computed tag */
  at_memset( computed, 0, 16 );

  return (diff == 0) ? 1 : 0;
}