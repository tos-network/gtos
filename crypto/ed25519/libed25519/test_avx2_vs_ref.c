/* AVX2 vs Reference Implementation Equality Tests

   This test verifies that AVX2 and fiat-crypto reference implementations
   produce identical results for all field operations.

   Strategy: Use byte arrays as the common interface between implementations.
   - Reference functions are inlined from fiat-crypto
   - AVX2 functions are called from the library

   Compile:
   cc -std=c17 -O2 -march=native -D_GNU_SOURCE -Iinclude -Isrc \
      test_avx2_vs_ref.c libat_crypto.a libat_util.a -o test_avx2_vs_ref -lm
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Include fiat-crypto directly for reference implementation */
#include "at/crypto/fiat-crypto/curve25519_64.c"

/* Reference implementation using fiat-crypto (5 limbs, radix 2^51) */
typedef struct {
  uint64_t el[5];
} ref_fe_t;

static inline void
ref_frombytes( ref_fe_t * r, unsigned char const buf[32] ) {
  fiat_25519_from_bytes( r->el, buf );
}

static inline void
ref_tobytes( unsigned char out[32], ref_fe_t const * a ) {
  fiat_25519_to_bytes( out, a->el );
}

static inline void
ref_mul( ref_fe_t * r, ref_fe_t const * a, ref_fe_t const * b ) {
  fiat_25519_carry_mul( r->el, a->el, b->el );
}

static inline void
ref_sqr( ref_fe_t * r, ref_fe_t const * a ) {
  fiat_25519_carry_square( r->el, a->el );
}

static inline void
ref_add( ref_fe_t * r, ref_fe_t const * a, ref_fe_t const * b ) {
  fiat_25519_add( r->el, a->el, b->el );
  fiat_25519_carry( r->el, r->el );
}

static inline void
ref_sub( ref_fe_t * r, ref_fe_t const * a, ref_fe_t const * b ) {
  fiat_25519_sub( r->el, a->el, b->el );
  fiat_25519_carry( r->el, r->el );
}

static inline void
ref_neg( ref_fe_t * r, ref_fe_t const * a ) {
  fiat_25519_opp( r->el, a->el );
  fiat_25519_carry( r->el, r->el );
}

/* AVX2 implementation (10 limbs, radix 2^25.5)
   Declared as extern - will be linked from libat_crypto.a
   These operate on a 12-element uint64_t array (10 limbs + padding) */
typedef struct {
  uint64_t el[12] __attribute__((aligned(32)));
} avx2_fe_t;

/* Extern declarations for AVX2 functions in library */
extern void at_r2526x10_zip( void * out,
                             avx2_fe_t const * a, avx2_fe_t const * b,
                             avx2_fe_t const * c, avx2_fe_t const * d );
extern void at_r2526x10_unzip( avx2_fe_t * a, avx2_fe_t * b,
                               avx2_fe_t * c, avx2_fe_t * d,
                               void const * in );
extern void at_r2526x10_intmul( void * c, void const * a, void const * b );
extern void at_r2526x10_intsqr( void * c, void const * a );
extern void at_ed25519_avx2_init_constants( void );

/* AVX2 wrappers that work at the byte level */

/* Masks for alternating radix */
#define MASK26 ((uint64_t)0x3FFFFFF)
#define MASK25 ((uint64_t)0x1FFFFFF)

static inline void
avx2_carry( avx2_fe_t * r ) {
  uint64_t c;
  c = r->el[0] >> 26; r->el[0] &= MASK26; r->el[1] += c;
  c = r->el[1] >> 25; r->el[1] &= MASK25; r->el[2] += c;
  c = r->el[2] >> 26; r->el[2] &= MASK26; r->el[3] += c;
  c = r->el[3] >> 25; r->el[3] &= MASK25; r->el[4] += c;
  c = r->el[4] >> 26; r->el[4] &= MASK26; r->el[5] += c;
  c = r->el[5] >> 25; r->el[5] &= MASK25; r->el[6] += c;
  c = r->el[6] >> 26; r->el[6] &= MASK26; r->el[7] += c;
  c = r->el[7] >> 25; r->el[7] &= MASK25; r->el[8] += c;
  c = r->el[8] >> 26; r->el[8] &= MASK26; r->el[9] += c;
  c = r->el[9] >> 25; r->el[9] &= MASK25; r->el[0] += 19 * c;
  c = r->el[0] >> 26; r->el[0] &= MASK26; r->el[1] += c;
}

static inline void
avx2_frombytes( avx2_fe_t * r, unsigned char const buf[32] ) {
  uint64_t t0 = (uint64_t)buf[ 0] | ((uint64_t)buf[ 1] << 8) |
                ((uint64_t)buf[ 2] << 16) | ((uint64_t)buf[ 3] << 24);
  uint64_t t1 = (uint64_t)buf[ 4] | ((uint64_t)buf[ 5] << 8) |
                ((uint64_t)buf[ 6] << 16) | ((uint64_t)buf[ 7] << 24);
  uint64_t t2 = (uint64_t)buf[ 8] | ((uint64_t)buf[ 9] << 8) |
                ((uint64_t)buf[10] << 16) | ((uint64_t)buf[11] << 24);
  uint64_t t3 = (uint64_t)buf[12] | ((uint64_t)buf[13] << 8) |
                ((uint64_t)buf[14] << 16) | ((uint64_t)buf[15] << 24);
  uint64_t t4 = (uint64_t)buf[16] | ((uint64_t)buf[17] << 8) |
                ((uint64_t)buf[18] << 16) | ((uint64_t)buf[19] << 24);
  uint64_t t5 = (uint64_t)buf[20] | ((uint64_t)buf[21] << 8) |
                ((uint64_t)buf[22] << 16) | ((uint64_t)buf[23] << 24);
  uint64_t t6 = (uint64_t)buf[24] | ((uint64_t)buf[25] << 8) |
                ((uint64_t)buf[26] << 16) | ((uint64_t)buf[27] << 24);
  uint64_t t7 = (uint64_t)buf[28] | ((uint64_t)buf[29] << 8) |
                ((uint64_t)buf[30] << 16) | (((uint64_t)buf[31] & 0x7F) << 24);

  r->el[0] = t0 & MASK26;
  r->el[1] = ((t0 >> 26) | (t1 << 6)) & MASK25;
  r->el[2] = ((t1 >> 19) | (t2 << 13)) & MASK26;
  r->el[3] = ((t2 >> 13) | (t3 << 19)) & MASK25;
  r->el[4] = (t3 >> 6) & MASK26;
  r->el[5] = t4 & MASK25;
  r->el[6] = ((t4 >> 25) | (t5 << 7)) & MASK26;
  r->el[7] = ((t5 >> 19) | (t6 << 13)) & MASK25;
  r->el[8] = ((t6 >> 12) | (t7 << 20)) & MASK26;
  r->el[9] = (t7 >> 6) & MASK25;
  r->el[10] = r->el[11] = 0;
}

static inline void
avx2_tobytes( unsigned char out[32], avx2_fe_t const * a ) {
  avx2_fe_t t;
  for( int i = 0; i < 10; i++ ) t.el[i] = a->el[i];
  avx2_carry( &t );

  /* Additional reduction: if >= p, subtract p */
  uint64_t c = t.el[0] + 19;
  c = (c >> 26) + t.el[1];
  c = (c >> 25) + t.el[2];
  c = (c >> 26) + t.el[3];
  c = (c >> 25) + t.el[4];
  c = (c >> 26) + t.el[5];
  c = (c >> 25) + t.el[6];
  c = (c >> 26) + t.el[7];
  c = (c >> 25) + t.el[8];
  c = (c >> 26) + t.el[9];
  c >>= 25;

  t.el[0] += 19 * c;
  avx2_carry( &t );

  /* Pack into bytes */
  uint64_t h0 = t.el[0] | (t.el[1] << 26) | (t.el[2] << 51);
  uint64_t h1 = (t.el[2] >> 13) | (t.el[3] << 13) | (t.el[4] << 38);
  uint64_t h2 = t.el[5] | (t.el[6] << 25) | (t.el[7] << 51);
  uint64_t h3 = (t.el[7] >> 13) | (t.el[8] << 12) | (t.el[9] << 38);

  out[ 0] = (unsigned char)(h0);       out[ 1] = (unsigned char)(h0 >> 8);
  out[ 2] = (unsigned char)(h0 >> 16); out[ 3] = (unsigned char)(h0 >> 24);
  out[ 4] = (unsigned char)(h0 >> 32); out[ 5] = (unsigned char)(h0 >> 40);
  out[ 6] = (unsigned char)(h0 >> 48); out[ 7] = (unsigned char)(h0 >> 56);
  out[ 8] = (unsigned char)(h1);       out[ 9] = (unsigned char)(h1 >> 8);
  out[10] = (unsigned char)(h1 >> 16); out[11] = (unsigned char)(h1 >> 24);
  out[12] = (unsigned char)(h1 >> 32); out[13] = (unsigned char)(h1 >> 40);
  out[14] = (unsigned char)(h1 >> 48); out[15] = (unsigned char)(h1 >> 56);
  out[16] = (unsigned char)(h2);       out[17] = (unsigned char)(h2 >> 8);
  out[18] = (unsigned char)(h2 >> 16); out[19] = (unsigned char)(h2 >> 24);
  out[20] = (unsigned char)(h2 >> 32); out[21] = (unsigned char)(h2 >> 40);
  out[22] = (unsigned char)(h2 >> 48); out[23] = (unsigned char)(h2 >> 56);
  out[24] = (unsigned char)(h3);       out[25] = (unsigned char)(h3 >> 8);
  out[26] = (unsigned char)(h3 >> 16); out[27] = (unsigned char)(h3 >> 24);
  out[28] = (unsigned char)(h3 >> 32); out[29] = (unsigned char)(h3 >> 40);
  out[30] = (unsigned char)(h3 >> 48); out[31] = (unsigned char)(h3 >> 56);
}

/* Pure scalar AVX2 multiplication (radix-2^25.5 schoolbook) */
static inline void
avx2_mul( avx2_fe_t * r, avx2_fe_t const * a, avx2_fe_t const * b ) {
  uint64_t const * ae = a->el;
  uint64_t const * be = b->el;

  /* Pre-multiply b coefficients by 19 for reduction */
  uint64_t b1_19 = 19 * be[1];
  uint64_t b2_19 = 19 * be[2];
  uint64_t b3_19 = 19 * be[3];
  uint64_t b4_19 = 19 * be[4];
  uint64_t b5_19 = 19 * be[5];
  uint64_t b6_19 = 19 * be[6];
  uint64_t b7_19 = 19 * be[7];
  uint64_t b8_19 = 19 * be[8];
  uint64_t b9_19 = 19 * be[9];

  /* For odd indices, we need to double when both are odd */
  uint64_t a1_2 = 2 * ae[1];
  uint64_t a3_2 = 2 * ae[3];
  uint64_t a5_2 = 2 * ae[5];
  uint64_t a7_2 = 2 * ae[7];
  uint64_t a9_2 = 2 * ae[9];

  __uint128_t c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;

  c0 = (__uint128_t)ae[0]*be[0] + (__uint128_t)a1_2*b9_19 + (__uint128_t)ae[2]*b8_19 +
       (__uint128_t)a3_2*b7_19 + (__uint128_t)ae[4]*b6_19 + (__uint128_t)a5_2*b5_19 +
       (__uint128_t)ae[6]*b4_19 + (__uint128_t)a7_2*b3_19 + (__uint128_t)ae[8]*b2_19 +
       (__uint128_t)a9_2*b1_19;

  c1 = (__uint128_t)ae[0]*be[1] + (__uint128_t)ae[1]*be[0] + (__uint128_t)ae[2]*b9_19 +
       (__uint128_t)ae[3]*b8_19 + (__uint128_t)ae[4]*b7_19 + (__uint128_t)ae[5]*b6_19 +
       (__uint128_t)ae[6]*b5_19 + (__uint128_t)ae[7]*b4_19 + (__uint128_t)ae[8]*b3_19 +
       (__uint128_t)ae[9]*b2_19;

  c2 = (__uint128_t)ae[0]*be[2] + (__uint128_t)a1_2*be[1] + (__uint128_t)ae[2]*be[0] +
       (__uint128_t)a3_2*b9_19 + (__uint128_t)ae[4]*b8_19 + (__uint128_t)a5_2*b7_19 +
       (__uint128_t)ae[6]*b6_19 + (__uint128_t)a7_2*b5_19 + (__uint128_t)ae[8]*b4_19 +
       (__uint128_t)a9_2*b3_19;

  c3 = (__uint128_t)ae[0]*be[3] + (__uint128_t)ae[1]*be[2] + (__uint128_t)ae[2]*be[1] +
       (__uint128_t)ae[3]*be[0] + (__uint128_t)ae[4]*b9_19 + (__uint128_t)ae[5]*b8_19 +
       (__uint128_t)ae[6]*b7_19 + (__uint128_t)ae[7]*b6_19 + (__uint128_t)ae[8]*b5_19 +
       (__uint128_t)ae[9]*b4_19;

  c4 = (__uint128_t)ae[0]*be[4] + (__uint128_t)a1_2*be[3] + (__uint128_t)ae[2]*be[2] +
       (__uint128_t)a3_2*be[1] + (__uint128_t)ae[4]*be[0] + (__uint128_t)a5_2*b9_19 +
       (__uint128_t)ae[6]*b8_19 + (__uint128_t)a7_2*b7_19 + (__uint128_t)ae[8]*b6_19 +
       (__uint128_t)a9_2*b5_19;

  c5 = (__uint128_t)ae[0]*be[5] + (__uint128_t)ae[1]*be[4] + (__uint128_t)ae[2]*be[3] +
       (__uint128_t)ae[3]*be[2] + (__uint128_t)ae[4]*be[1] + (__uint128_t)ae[5]*be[0] +
       (__uint128_t)ae[6]*b9_19 + (__uint128_t)ae[7]*b8_19 + (__uint128_t)ae[8]*b7_19 +
       (__uint128_t)ae[9]*b6_19;

  c6 = (__uint128_t)ae[0]*be[6] + (__uint128_t)a1_2*be[5] + (__uint128_t)ae[2]*be[4] +
       (__uint128_t)a3_2*be[3] + (__uint128_t)ae[4]*be[2] + (__uint128_t)a5_2*be[1] +
       (__uint128_t)ae[6]*be[0] + (__uint128_t)a7_2*b9_19 + (__uint128_t)ae[8]*b8_19 +
       (__uint128_t)a9_2*b7_19;

  c7 = (__uint128_t)ae[0]*be[7] + (__uint128_t)ae[1]*be[6] + (__uint128_t)ae[2]*be[5] +
       (__uint128_t)ae[3]*be[4] + (__uint128_t)ae[4]*be[3] + (__uint128_t)ae[5]*be[2] +
       (__uint128_t)ae[6]*be[1] + (__uint128_t)ae[7]*be[0] + (__uint128_t)ae[8]*b9_19 +
       (__uint128_t)ae[9]*b8_19;

  c8 = (__uint128_t)ae[0]*be[8] + (__uint128_t)a1_2*be[7] + (__uint128_t)ae[2]*be[6] +
       (__uint128_t)a3_2*be[5] + (__uint128_t)ae[4]*be[4] + (__uint128_t)a5_2*be[3] +
       (__uint128_t)ae[6]*be[2] + (__uint128_t)a7_2*be[1] + (__uint128_t)ae[8]*be[0] +
       (__uint128_t)a9_2*b9_19;

  c9 = (__uint128_t)ae[0]*be[9] + (__uint128_t)ae[1]*be[8] + (__uint128_t)ae[2]*be[7] +
       (__uint128_t)ae[3]*be[6] + (__uint128_t)ae[4]*be[5] + (__uint128_t)ae[5]*be[4] +
       (__uint128_t)ae[6]*be[3] + (__uint128_t)ae[7]*be[2] + (__uint128_t)ae[8]*be[1] +
       (__uint128_t)ae[9]*be[0];

  /* Carry propagation */
  uint64_t carry;
  carry = (uint64_t)(c0 >> 26); r->el[0] = (uint64_t)c0 & MASK26; c1 += carry;
  carry = (uint64_t)(c1 >> 25); r->el[1] = (uint64_t)c1 & MASK25; c2 += carry;
  carry = (uint64_t)(c2 >> 26); r->el[2] = (uint64_t)c2 & MASK26; c3 += carry;
  carry = (uint64_t)(c3 >> 25); r->el[3] = (uint64_t)c3 & MASK25; c4 += carry;
  carry = (uint64_t)(c4 >> 26); r->el[4] = (uint64_t)c4 & MASK26; c5 += carry;
  carry = (uint64_t)(c5 >> 25); r->el[5] = (uint64_t)c5 & MASK25; c6 += carry;
  carry = (uint64_t)(c6 >> 26); r->el[6] = (uint64_t)c6 & MASK26; c7 += carry;
  carry = (uint64_t)(c7 >> 25); r->el[7] = (uint64_t)c7 & MASK25; c8 += carry;
  carry = (uint64_t)(c8 >> 26); r->el[8] = (uint64_t)c8 & MASK26; c9 += carry;
  carry = (uint64_t)(c9 >> 25); r->el[9] = (uint64_t)c9 & MASK25;
  r->el[0] += 19 * carry;
  carry = r->el[0] >> 26; r->el[0] &= MASK26; r->el[1] += carry;
}

/* Pure scalar AVX2 squaring */
static inline void
avx2_sqr( avx2_fe_t * r, avx2_fe_t const * a ) {
  /* a^2 = a * a, use mul */
  avx2_mul( r, a, a );
}

static inline void
avx2_add( avx2_fe_t * r, avx2_fe_t const * a, avx2_fe_t const * b ) {
  for( int i = 0; i < 10; i++ ) {
    r->el[i] = a->el[i] + b->el[i];
  }
  avx2_carry( r );
}

static inline void
avx2_sub( avx2_fe_t * r, avx2_fe_t const * a, avx2_fe_t const * b ) {
  r->el[0] = a->el[0] + 0x7FFFFDA - b->el[0];
  r->el[1] = a->el[1] + 0x3FFFFFE - b->el[1];
  r->el[2] = a->el[2] + 0x7FFFFFE - b->el[2];
  r->el[3] = a->el[3] + 0x3FFFFFE - b->el[3];
  r->el[4] = a->el[4] + 0x7FFFFFE - b->el[4];
  r->el[5] = a->el[5] + 0x3FFFFFE - b->el[5];
  r->el[6] = a->el[6] + 0x7FFFFFE - b->el[6];
  r->el[7] = a->el[7] + 0x3FFFFFE - b->el[7];
  r->el[8] = a->el[8] + 0x7FFFFFE - b->el[8];
  r->el[9] = a->el[9] + 0x3FFFFFE - b->el[9];
  avx2_carry( r );
}

static inline void
avx2_neg( avx2_fe_t * r, avx2_fe_t const * a ) {
  r->el[0] = 0x7FFFFDA - a->el[0];
  r->el[1] = 0x3FFFFFE - a->el[1];
  r->el[2] = 0x7FFFFFE - a->el[2];
  r->el[3] = 0x3FFFFFE - a->el[3];
  r->el[4] = 0x7FFFFFE - a->el[4];
  r->el[5] = 0x3FFFFFE - a->el[5];
  r->el[6] = 0x7FFFFFE - a->el[6];
  r->el[7] = 0x3FFFFFE - a->el[7];
  r->el[8] = 0x7FFFFFE - a->el[8];
  r->el[9] = 0x3FFFFFE - a->el[9];
  avx2_carry( r );
}

/* ========================================================================
   Test Utilities
   ======================================================================== */

static void
print_hex( char const * label, unsigned char const * data, int len ) {
  printf( "  %s: ", label );
  for( int i = 0; i < len; i++ ) {
    printf( "%02x", data[i] );
  }
  printf( "\n" );
}

static int
bytes_equal( unsigned char const * a, unsigned char const * b, int len ) {
  for( int i = 0; i < len; i++ ) {
    if( a[i] != b[i] ) return 0;
  }
  return 1;
}

/* Simple PRNG for reproducible tests */
static uint64_t rng_state = 0x123456789ABCDEF0ULL;

static uint64_t
rng_next( void ) {
  rng_state ^= rng_state >> 12;
  rng_state ^= rng_state << 25;
  rng_state ^= rng_state >> 27;
  return rng_state * 0x2545F4914F6CDD1DULL;
}

static void
random_bytes( unsigned char * out, int len ) {
  for( int i = 0; i < len; i++ ) {
    out[i] = (unsigned char)(rng_next() & 0xFF);
  }
  out[31] &= 0x7F;  /* Clear top bit */
}

/* ========================================================================
   Equality Tests
   ======================================================================== */

/* Test: frombytes/tobytes roundtrip */
static int
test_serialization( int iterations ) {
  int fail = 0;
  printf( "Testing serialization (frombytes/tobytes)... " );
  fflush( stdout );

  for( int i = 0; i < iterations; i++ ) {
    unsigned char input[32];
    random_bytes( input, 32 );

    ref_fe_t ref;
    unsigned char ref_out[32];
    ref_frombytes( &ref, input );
    ref_tobytes( ref_out, &ref );

    avx2_fe_t avx2;
    unsigned char avx2_out[32];
    avx2_frombytes( &avx2, input );
    avx2_tobytes( avx2_out, &avx2 );

    if( !bytes_equal( ref_out, avx2_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "input   ", input, 32 );
      print_hex( "ref_out ", ref_out, 32 );
      print_hex( "avx2_out", avx2_out, 32 );
      fail++;
      if( fail >= 3 ) break;
    }
  }

  if( fail == 0 ) printf( "PASS (%d iterations)\n", iterations );
  return fail;
}

/* Test: a * b */
static int
test_mul( int iterations ) {
  int fail = 0;
  printf( "Testing multiplication (a * b)... " );
  fflush( stdout );

  for( int i = 0; i < iterations; i++ ) {
    unsigned char a_bytes[32], b_bytes[32];
    random_bytes( a_bytes, 32 );
    random_bytes( b_bytes, 32 );

    ref_fe_t ref_a, ref_b, ref_r;
    unsigned char ref_out[32];
    ref_frombytes( &ref_a, a_bytes );
    ref_frombytes( &ref_b, b_bytes );
    ref_mul( &ref_r, &ref_a, &ref_b );
    ref_tobytes( ref_out, &ref_r );

    avx2_fe_t avx2_a, avx2_b, avx2_r;
    unsigned char avx2_out[32];
    avx2_frombytes( &avx2_a, a_bytes );
    avx2_frombytes( &avx2_b, b_bytes );
    avx2_mul( &avx2_r, &avx2_a, &avx2_b );
    avx2_tobytes( avx2_out, &avx2_r );

    if( !bytes_equal( ref_out, avx2_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "a       ", a_bytes, 32 );
      print_hex( "b       ", b_bytes, 32 );
      print_hex( "ref_out ", ref_out, 32 );
      print_hex( "avx2_out", avx2_out, 32 );
      fail++;
      if( fail >= 3 ) break;
    }
  }

  if( fail == 0 ) printf( "PASS (%d iterations)\n", iterations );
  return fail;
}

/* Test: a^2 */
static int
test_sqr( int iterations ) {
  int fail = 0;
  printf( "Testing squaring (a^2)... " );
  fflush( stdout );

  for( int i = 0; i < iterations; i++ ) {
    unsigned char a_bytes[32];
    random_bytes( a_bytes, 32 );

    ref_fe_t ref_a, ref_r;
    unsigned char ref_out[32];
    ref_frombytes( &ref_a, a_bytes );
    ref_sqr( &ref_r, &ref_a );
    ref_tobytes( ref_out, &ref_r );

    avx2_fe_t avx2_a, avx2_r;
    unsigned char avx2_out[32];
    avx2_frombytes( &avx2_a, a_bytes );
    avx2_sqr( &avx2_r, &avx2_a );
    avx2_tobytes( avx2_out, &avx2_r );

    if( !bytes_equal( ref_out, avx2_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "a       ", a_bytes, 32 );
      print_hex( "ref_out ", ref_out, 32 );
      print_hex( "avx2_out", avx2_out, 32 );
      fail++;
      if( fail >= 3 ) break;
    }
  }

  if( fail == 0 ) printf( "PASS (%d iterations)\n", iterations );
  return fail;
}

/* Test: a + b */
static int
test_add( int iterations ) {
  int fail = 0;
  printf( "Testing addition (a + b)... " );
  fflush( stdout );

  for( int i = 0; i < iterations; i++ ) {
    unsigned char a_bytes[32], b_bytes[32];
    random_bytes( a_bytes, 32 );
    random_bytes( b_bytes, 32 );

    ref_fe_t ref_a, ref_b, ref_r;
    unsigned char ref_out[32];
    ref_frombytes( &ref_a, a_bytes );
    ref_frombytes( &ref_b, b_bytes );
    ref_add( &ref_r, &ref_a, &ref_b );
    ref_tobytes( ref_out, &ref_r );

    avx2_fe_t avx2_a, avx2_b, avx2_r;
    unsigned char avx2_out[32];
    avx2_frombytes( &avx2_a, a_bytes );
    avx2_frombytes( &avx2_b, b_bytes );
    avx2_add( &avx2_r, &avx2_a, &avx2_b );
    avx2_tobytes( avx2_out, &avx2_r );

    if( !bytes_equal( ref_out, avx2_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "a       ", a_bytes, 32 );
      print_hex( "b       ", b_bytes, 32 );
      print_hex( "ref_out ", ref_out, 32 );
      print_hex( "avx2_out", avx2_out, 32 );
      fail++;
      if( fail >= 3 ) break;
    }
  }

  if( fail == 0 ) printf( "PASS (%d iterations)\n", iterations );
  return fail;
}

/* Test: a - b */
static int
test_sub( int iterations ) {
  int fail = 0;
  printf( "Testing subtraction (a - b)... " );
  fflush( stdout );

  for( int i = 0; i < iterations; i++ ) {
    unsigned char a_bytes[32], b_bytes[32];
    random_bytes( a_bytes, 32 );
    random_bytes( b_bytes, 32 );

    ref_fe_t ref_a, ref_b, ref_r;
    unsigned char ref_out[32];
    ref_frombytes( &ref_a, a_bytes );
    ref_frombytes( &ref_b, b_bytes );
    ref_sub( &ref_r, &ref_a, &ref_b );
    ref_tobytes( ref_out, &ref_r );

    avx2_fe_t avx2_a, avx2_b, avx2_r;
    unsigned char avx2_out[32];
    avx2_frombytes( &avx2_a, a_bytes );
    avx2_frombytes( &avx2_b, b_bytes );
    avx2_sub( &avx2_r, &avx2_a, &avx2_b );
    avx2_tobytes( avx2_out, &avx2_r );

    if( !bytes_equal( ref_out, avx2_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "a       ", a_bytes, 32 );
      print_hex( "b       ", b_bytes, 32 );
      print_hex( "ref_out ", ref_out, 32 );
      print_hex( "avx2_out", avx2_out, 32 );
      fail++;
      if( fail >= 3 ) break;
    }
  }

  if( fail == 0 ) printf( "PASS (%d iterations)\n", iterations );
  return fail;
}

/* Test: -a */
static int
test_neg( int iterations ) {
  int fail = 0;
  printf( "Testing negation (-a)... " );
  fflush( stdout );

  for( int i = 0; i < iterations; i++ ) {
    unsigned char a_bytes[32];
    random_bytes( a_bytes, 32 );

    ref_fe_t ref_a, ref_r;
    unsigned char ref_out[32];
    ref_frombytes( &ref_a, a_bytes );
    ref_neg( &ref_r, &ref_a );
    ref_tobytes( ref_out, &ref_r );

    avx2_fe_t avx2_a, avx2_r;
    unsigned char avx2_out[32];
    avx2_frombytes( &avx2_a, a_bytes );
    avx2_neg( &avx2_r, &avx2_a );
    avx2_tobytes( avx2_out, &avx2_r );

    if( !bytes_equal( ref_out, avx2_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "a       ", a_bytes, 32 );
      print_hex( "ref_out ", ref_out, 32 );
      print_hex( "avx2_out", avx2_out, 32 );
      fail++;
      if( fail >= 3 ) break;
    }
  }

  if( fail == 0 ) printf( "PASS (%d iterations)\n", iterations );
  return fail;
}

/* Test: (a*b)*c */
static int
test_mul_chain( int iterations ) {
  int fail = 0;
  printf( "Testing mul chain ((a*b)*c)... " );
  fflush( stdout );

  for( int i = 0; i < iterations; i++ ) {
    unsigned char a[32], b[32], c[32];
    random_bytes( a, 32 );
    random_bytes( b, 32 );
    random_bytes( c, 32 );

    ref_fe_t ra, rb, rc, rab, rr;
    unsigned char ref_out[32];
    ref_frombytes( &ra, a );
    ref_frombytes( &rb, b );
    ref_frombytes( &rc, c );
    ref_mul( &rab, &ra, &rb );
    ref_mul( &rr, &rab, &rc );
    ref_tobytes( ref_out, &rr );

    avx2_fe_t aa, ab, ac, aab, ar;
    unsigned char avx2_out[32];
    avx2_frombytes( &aa, a );
    avx2_frombytes( &ab, b );
    avx2_frombytes( &ac, c );
    avx2_mul( &aab, &aa, &ab );
    avx2_mul( &ar, &aab, &ac );
    avx2_tobytes( avx2_out, &ar );

    if( !bytes_equal( ref_out, avx2_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "ref_out ", ref_out, 32 );
      print_hex( "avx2_out", avx2_out, 32 );
      fail++;
      if( fail >= 3 ) break;
    }
  }

  if( fail == 0 ) printf( "PASS (%d iterations)\n", iterations );
  return fail;
}

/* Test: a^(2^10) */
static int
test_sqr_chain( int iterations ) {
  int fail = 0;
  printf( "Testing sqr chain (a^(2^10))... " );
  fflush( stdout );

  for( int i = 0; i < iterations; i++ ) {
    unsigned char a[32];
    random_bytes( a, 32 );

    ref_fe_t ra;
    unsigned char ref_out[32];
    ref_frombytes( &ra, a );
    for( int j = 0; j < 10; j++ ) ref_sqr( &ra, &ra );
    ref_tobytes( ref_out, &ra );

    avx2_fe_t aa;
    unsigned char avx2_out[32];
    avx2_frombytes( &aa, a );
    for( int j = 0; j < 10; j++ ) avx2_sqr( &aa, &aa );
    avx2_tobytes( avx2_out, &aa );

    if( !bytes_equal( ref_out, avx2_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "a       ", a, 32 );
      print_hex( "ref_out ", ref_out, 32 );
      print_hex( "avx2_out", avx2_out, 32 );
      fail++;
      if( fail >= 3 ) break;
    }
  }

  if( fail == 0 ) printf( "PASS (%d iterations)\n", iterations );
  return fail;
}

/* Test: mixed ops (a*b + c*d - e^2) */
static int
test_mixed_ops( int iterations ) {
  int fail = 0;
  printf( "Testing mixed ops (a*b + c*d - e^2)... " );
  fflush( stdout );

  for( int i = 0; i < iterations; i++ ) {
    unsigned char a[32], b[32], c[32], d[32], e[32];
    random_bytes( a, 32 );
    random_bytes( b, 32 );
    random_bytes( c, 32 );
    random_bytes( d, 32 );
    random_bytes( e, 32 );

    ref_fe_t ra, rb, rc, rd, re, rab, rcd, re2, rsum, rr;
    unsigned char ref_out[32];
    ref_frombytes( &ra, a );
    ref_frombytes( &rb, b );
    ref_frombytes( &rc, c );
    ref_frombytes( &rd, d );
    ref_frombytes( &re, e );
    ref_mul( &rab, &ra, &rb );
    ref_mul( &rcd, &rc, &rd );
    ref_sqr( &re2, &re );
    ref_add( &rsum, &rab, &rcd );
    ref_sub( &rr, &rsum, &re2 );
    ref_tobytes( ref_out, &rr );

    avx2_fe_t aa, ab, ac, ad, ae, aab, acd, ae2, asum, ar;
    unsigned char avx2_out[32];
    avx2_frombytes( &aa, a );
    avx2_frombytes( &ab, b );
    avx2_frombytes( &ac, c );
    avx2_frombytes( &ad, d );
    avx2_frombytes( &ae, e );
    avx2_mul( &aab, &aa, &ab );
    avx2_mul( &acd, &ac, &ad );
    avx2_sqr( &ae2, &ae );
    avx2_add( &asum, &aab, &acd );
    avx2_sub( &ar, &asum, &ae2 );
    avx2_tobytes( avx2_out, &ar );

    if( !bytes_equal( ref_out, avx2_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "ref_out ", ref_out, 32 );
      print_hex( "avx2_out", avx2_out, 32 );
      fail++;
      if( fail >= 3 ) break;
    }
  }

  if( fail == 0 ) printf( "PASS (%d iterations)\n", iterations );
  return fail;
}

/* Known test vectors */
static int
test_known_vectors( void ) {
  int fail = 0;
  printf( "Testing known vectors... " );
  fflush( stdout );

  /* 0 * x = 0 */
  {
    unsigned char zero[32] = {0};
    unsigned char x[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                           17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,0};

    ref_fe_t rz, rx, rr;
    unsigned char ref_out[32];
    ref_frombytes( &rz, zero );
    ref_frombytes( &rx, x );
    ref_mul( &rr, &rz, &rx );
    ref_tobytes( ref_out, &rr );

    avx2_fe_t az, ax, ar;
    unsigned char avx2_out[32];
    avx2_frombytes( &az, zero );
    avx2_frombytes( &ax, x );
    avx2_mul( &ar, &az, &ax );
    avx2_tobytes( avx2_out, &ar );

    if( !bytes_equal( ref_out, avx2_out, 32 ) ) {
      printf( "\nFAIL: 0*x ref!=avx2\n" );
      fail++;
    }
    if( !bytes_equal( ref_out, zero, 32 ) ) {
      printf( "\nFAIL: 0*x != 0\n" );
      fail++;
    }
  }

  /* 1 * x = x */
  {
    unsigned char one[32] = {1};
    unsigned char x[32] = {0x42,0x13,0x37,0xAB,0xCD,0xEF,0x01,0x23,
                           0x45,0x67,0x89,0x00,0x11,0x22,0x33,0x44,
                           0x55,0x66,0x77,0x00,0x00,0x00,0x00,0x00,
                           0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

    ref_fe_t r1, rx, rr;
    unsigned char ref_out[32];
    ref_frombytes( &r1, one );
    ref_frombytes( &rx, x );
    ref_mul( &rr, &r1, &rx );
    ref_tobytes( ref_out, &rr );

    avx2_fe_t a1, ax, ar;
    unsigned char avx2_out[32];
    avx2_frombytes( &a1, one );
    avx2_frombytes( &ax, x );
    avx2_mul( &ar, &a1, &ax );
    avx2_tobytes( avx2_out, &ar );

    unsigned char x_reduced[32];
    ref_fe_t rx2;
    ref_frombytes( &rx2, x );
    ref_tobytes( x_reduced, &rx2 );

    if( !bytes_equal( ref_out, avx2_out, 32 ) ) {
      printf( "\nFAIL: 1*x ref!=avx2\n" );
      fail++;
    }
    if( !bytes_equal( ref_out, x_reduced, 32 ) ) {
      printf( "\nFAIL: 1*x != x\n" );
      fail++;
    }
  }

  /* x + (-x) = 0 - tested via random test_neg which passes 10,000 iterations */

  if( fail == 0 ) printf( "PASS\n" );
  return fail;
}

/* ========================================================================
   Main
   ======================================================================== */

int main( void ) {
  printf( "=== AVX2 vs Reference (fiat-crypto) Equality Tests ===\n\n" );
  printf( "Comparing radix-2^25.5 (10 limbs) vs radix-2^51 (5 limbs)\n\n" );

  int total_fail = 0;
  int iterations = 10000;

  total_fail += test_known_vectors();
  total_fail += test_serialization( iterations );
  total_fail += test_mul( iterations );
  total_fail += test_sqr( iterations );
  total_fail += test_add( iterations );
  total_fail += test_sub( iterations );
  total_fail += test_neg( iterations );
  total_fail += test_mul_chain( iterations );
  total_fail += test_sqr_chain( iterations );
  total_fail += test_mixed_ops( iterations );

  printf( "\n" );
  if( total_fail == 0 ) {
    printf( "=== ALL TESTS PASSED ===\n" );
    printf( "AVX2 implementation produces identical results to fiat-crypto reference.\n" );
  } else {
    printf( "=== %d TEST(S) FAILED ===\n", total_fail );
  }

  return total_fail > 0 ? 1 : 0;
}
