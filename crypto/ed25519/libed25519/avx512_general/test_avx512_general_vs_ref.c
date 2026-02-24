/* AVX-512F General vs Reference Implementation Equality Tests

   This test verifies that AVX-512F General and fiat-crypto reference implementations
   produce identical results for all field operations.

   Strategy: Use byte arrays as the common interface between implementations.
   - Reference functions are inlined from fiat-crypto
   - AVX-512F functions use the at_f25519_t type with radix-2^25.5

   Compile (standalone):
   cc -std=c17 -O2 -march=skylake-avx512 -D_GNU_SOURCE -DAT_HAS_AVX512=1 \
      -DAT_HAS_AVX512_GENERAL=1 -Iinclude -Isrc -Isrc/crypto/ed25519 \
      test_avx512_general_vs_ref.c -o test_avx512_general_vs_ref -lm
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

/* AVX-512F General implementation (10 limbs, radix 2^25.5)
   This matches the AVX2 representation but uses 8-way SIMD internally.

   Note: Include directly from the local directory to avoid conflicts
   with the main header dispatcher during development/testing. */

#if AT_HAS_AVX512_GENERAL

/* Include the local AVX-512 General implementation directly */
#include "at_f25519.h"  /* Local to avx512_general directory */

typedef at_f25519_t avx512_fe_t;

#define avx512_frombytes at_f25519_frombytes
#define avx512_tobytes at_f25519_tobytes

static inline void
avx512_mul( avx512_fe_t * r, avx512_fe_t const * a, avx512_fe_t const * b ) {
  at_f25519_mul( r, a, b );
}

static inline void
avx512_sqr( avx512_fe_t * r, avx512_fe_t const * a ) {
  at_f25519_sqr( r, a );
}

static inline void
avx512_add( avx512_fe_t * r, avx512_fe_t const * a, avx512_fe_t const * b ) {
  at_f25519_add( r, a, b );
}

static inline void
avx512_sub( avx512_fe_t * r, avx512_fe_t const * a, avx512_fe_t const * b ) {
  at_f25519_sub( r, a, b );
}

static inline void
avx512_neg( avx512_fe_t * r, avx512_fe_t const * a ) {
  at_f25519_neg( r, a );
  at_f25519_carry( r );
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

    avx512_fe_t avx512;
    unsigned char avx512_out[32];
    avx512_frombytes( &avx512, input );
    avx512_tobytes( avx512_out, &avx512 );

    if( !bytes_equal( ref_out, avx512_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "input     ", input, 32 );
      print_hex( "ref_out   ", ref_out, 32 );
      print_hex( "avx512_out", avx512_out, 32 );
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

    avx512_fe_t avx512_a, avx512_b, avx512_r;
    unsigned char avx512_out[32];
    avx512_frombytes( &avx512_a, a_bytes );
    avx512_frombytes( &avx512_b, b_bytes );
    avx512_mul( &avx512_r, &avx512_a, &avx512_b );
    avx512_tobytes( avx512_out, &avx512_r );

    if( !bytes_equal( ref_out, avx512_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "a         ", a_bytes, 32 );
      print_hex( "b         ", b_bytes, 32 );
      print_hex( "ref_out   ", ref_out, 32 );
      print_hex( "avx512_out", avx512_out, 32 );
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

    avx512_fe_t avx512_a, avx512_r;
    unsigned char avx512_out[32];
    avx512_frombytes( &avx512_a, a_bytes );
    avx512_sqr( &avx512_r, &avx512_a );
    avx512_tobytes( avx512_out, &avx512_r );

    if( !bytes_equal( ref_out, avx512_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "a         ", a_bytes, 32 );
      print_hex( "ref_out   ", ref_out, 32 );
      print_hex( "avx512_out", avx512_out, 32 );
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

    avx512_fe_t avx512_a, avx512_b, avx512_r;
    unsigned char avx512_out[32];
    avx512_frombytes( &avx512_a, a_bytes );
    avx512_frombytes( &avx512_b, b_bytes );
    avx512_add( &avx512_r, &avx512_a, &avx512_b );
    avx512_tobytes( avx512_out, &avx512_r );

    if( !bytes_equal( ref_out, avx512_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "a         ", a_bytes, 32 );
      print_hex( "b         ", b_bytes, 32 );
      print_hex( "ref_out   ", ref_out, 32 );
      print_hex( "avx512_out", avx512_out, 32 );
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

    avx512_fe_t avx512_a, avx512_b, avx512_r;
    unsigned char avx512_out[32];
    avx512_frombytes( &avx512_a, a_bytes );
    avx512_frombytes( &avx512_b, b_bytes );
    avx512_sub( &avx512_r, &avx512_a, &avx512_b );
    avx512_tobytes( avx512_out, &avx512_r );

    if( !bytes_equal( ref_out, avx512_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "a         ", a_bytes, 32 );
      print_hex( "b         ", b_bytes, 32 );
      print_hex( "ref_out   ", ref_out, 32 );
      print_hex( "avx512_out", avx512_out, 32 );
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

    avx512_fe_t avx512_a, avx512_r;
    unsigned char avx512_out[32];
    avx512_frombytes( &avx512_a, a_bytes );
    avx512_neg( &avx512_r, &avx512_a );
    avx512_tobytes( avx512_out, &avx512_r );

    if( !bytes_equal( ref_out, avx512_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "a         ", a_bytes, 32 );
      print_hex( "ref_out   ", ref_out, 32 );
      print_hex( "avx512_out", avx512_out, 32 );
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

    avx512_fe_t aa, ab, ac, aab, ar;
    unsigned char avx512_out[32];
    avx512_frombytes( &aa, a );
    avx512_frombytes( &ab, b );
    avx512_frombytes( &ac, c );
    avx512_mul( &aab, &aa, &ab );
    avx512_mul( &ar, &aab, &ac );
    avx512_tobytes( avx512_out, &ar );

    if( !bytes_equal( ref_out, avx512_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "ref_out   ", ref_out, 32 );
      print_hex( "avx512_out", avx512_out, 32 );
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

    avx512_fe_t aa;
    unsigned char avx512_out[32];
    avx512_frombytes( &aa, a );
    for( int j = 0; j < 10; j++ ) avx512_sqr( &aa, &aa );
    avx512_tobytes( avx512_out, &aa );

    if( !bytes_equal( ref_out, avx512_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "a         ", a, 32 );
      print_hex( "ref_out   ", ref_out, 32 );
      print_hex( "avx512_out", avx512_out, 32 );
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

    avx512_fe_t aa, ab, ac, ad, ae, aab, acd, ae2, asum, ar;
    unsigned char avx512_out[32];
    avx512_frombytes( &aa, a );
    avx512_frombytes( &ab, b );
    avx512_frombytes( &ac, c );
    avx512_frombytes( &ad, d );
    avx512_frombytes( &ae, e );
    avx512_mul( &aab, &aa, &ab );
    avx512_mul( &acd, &ac, &ad );
    avx512_sqr( &ae2, &ae );
    avx512_add( &asum, &aab, &acd );
    avx512_sub( &ar, &asum, &ae2 );
    avx512_tobytes( avx512_out, &ar );

    if( !bytes_equal( ref_out, avx512_out, 32 ) ) {
      printf( "\nFAIL at iteration %d\n", i );
      print_hex( "ref_out   ", ref_out, 32 );
      print_hex( "avx512_out", avx512_out, 32 );
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

    avx512_fe_t az, ax, ar;
    unsigned char avx512_out[32];
    avx512_frombytes( &az, zero );
    avx512_frombytes( &ax, x );
    avx512_mul( &ar, &az, &ax );
    avx512_tobytes( avx512_out, &ar );

    if( !bytes_equal( ref_out, avx512_out, 32 ) ) {
      printf( "\nFAIL: 0*x ref!=avx512\n" );
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

    avx512_fe_t a1, ax, ar;
    unsigned char avx512_out[32];
    avx512_frombytes( &a1, one );
    avx512_frombytes( &ax, x );
    avx512_mul( &ar, &a1, &ax );
    avx512_tobytes( avx512_out, &ar );

    unsigned char x_reduced[32];
    ref_fe_t rx2;
    ref_frombytes( &rx2, x );
    ref_tobytes( x_reduced, &rx2 );

    if( !bytes_equal( ref_out, avx512_out, 32 ) ) {
      printf( "\nFAIL: 1*x ref!=avx512\n" );
      fail++;
    }
    if( !bytes_equal( ref_out, x_reduced, 32 ) ) {
      printf( "\nFAIL: 1*x != x\n" );
      fail++;
    }
  }

  if( fail == 0 ) printf( "PASS\n" );
  return fail;
}

/* Test 8-way SIMD operations match scalar */
static int
test_mul8_consistency( int iterations ) {
  int fail = 0;
  printf( "Testing mul8 vs scalar consistency... " );
  fflush( stdout );

  for( int i = 0; i < iterations; i++ ) {
    unsigned char a[8][32], b[8][32];
    for( int j = 0; j < 8; j++ ) {
      random_bytes( a[j], 32 );
      random_bytes( b[j], 32 );
    }

    /* Scalar: 8 individual multiplications */
    avx512_fe_t fa[8], fb[8], fs[8];
    unsigned char scalar_out[8][32];
    for( int j = 0; j < 8; j++ ) {
      avx512_frombytes( &fa[j], a[j] );
      avx512_frombytes( &fb[j], b[j] );
      avx512_mul( &fs[j], &fa[j], &fb[j] );
      avx512_tobytes( scalar_out[j], &fs[j] );
    }

    /* SIMD: 8-way parallel multiplication */
    avx512_fe_t fp[8];
    at_f25519_mul8( &fp[0], &fa[0], &fb[0],
                    &fp[1], &fa[1], &fb[1],
                    &fp[2], &fa[2], &fb[2],
                    &fp[3], &fa[3], &fb[3],
                    &fp[4], &fa[4], &fb[4],
                    &fp[5], &fa[5], &fb[5],
                    &fp[6], &fa[6], &fb[6],
                    &fp[7], &fa[7], &fb[7] );

    unsigned char simd_out[8][32];
    for( int j = 0; j < 8; j++ ) {
      avx512_tobytes( simd_out[j], &fp[j] );
    }

    /* Compare all 8 results */
    int mismatch = 0;
    for( int j = 0; j < 8; j++ ) {
      if( !bytes_equal( scalar_out[j], simd_out[j], 32 ) ) {
        mismatch = 1;
        break;
      }
    }

    if( mismatch ) {
      printf( "\nFAIL at iteration %d\n", i );
      for( int j = 0; j < 8; j++ ) {
        if( !bytes_equal( scalar_out[j], simd_out[j], 32 ) ) {
          printf( "  Element %d mismatch:\n", j );
          print_hex( "  scalar", scalar_out[j], 32 );
          print_hex( "  simd  ", simd_out[j], 32 );
        }
      }
      fail++;
      if( fail >= 3 ) break;
    }
  }

  if( fail == 0 ) printf( "PASS (%d iterations)\n", iterations );
  return fail;
}

/* Test 8-way SIMD squaring matches scalar */
static int
test_sqr8_consistency( int iterations ) {
  int fail = 0;
  printf( "Testing sqr8 vs scalar consistency... " );
  fflush( stdout );

  for( int i = 0; i < iterations; i++ ) {
    unsigned char a[8][32];
    for( int j = 0; j < 8; j++ ) {
      random_bytes( a[j], 32 );
    }

    /* Scalar: 8 individual squarings */
    avx512_fe_t fa[8], fs[8];
    unsigned char scalar_out[8][32];
    for( int j = 0; j < 8; j++ ) {
      avx512_frombytes( &fa[j], a[j] );
      avx512_sqr( &fs[j], &fa[j] );
      avx512_tobytes( scalar_out[j], &fs[j] );
    }

    /* SIMD: 8-way parallel squaring */
    avx512_fe_t fp[8];
    at_f25519_sqr8( &fp[0], &fa[0],
                    &fp[1], &fa[1],
                    &fp[2], &fa[2],
                    &fp[3], &fa[3],
                    &fp[4], &fa[4],
                    &fp[5], &fa[5],
                    &fp[6], &fa[6],
                    &fp[7], &fa[7] );

    unsigned char simd_out[8][32];
    for( int j = 0; j < 8; j++ ) {
      avx512_tobytes( simd_out[j], &fp[j] );
    }

    /* Compare all 8 results */
    int mismatch = 0;
    for( int j = 0; j < 8; j++ ) {
      if( !bytes_equal( scalar_out[j], simd_out[j], 32 ) ) {
        mismatch = 1;
        break;
      }
    }

    if( mismatch ) {
      printf( "\nFAIL at iteration %d\n", i );
      fail++;
      if( fail >= 3 ) break;
    }
  }

  if( fail == 0 ) printf( "PASS (%d iterations)\n", iterations );
  return fail;
}

/* ========================================================================
   Main
   ======================================================================== */

int main( void ) {
  printf( "=== AVX-512F General vs Reference (fiat-crypto) Equality Tests ===\n\n" );
  printf( "Comparing radix-2^25.5 (10 limbs, AVX-512F) vs radix-2^51 (5 limbs, fiat)\n\n" );

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
  total_fail += test_mul8_consistency( 1000 );
  total_fail += test_sqr8_consistency( 1000 );

  printf( "\n" );
  if( total_fail == 0 ) {
    printf( "=== ALL TESTS PASSED ===\n" );
    printf( "AVX-512F General implementation produces identical results to fiat-crypto reference.\n" );
  } else {
    printf( "=== %d TEST(S) FAILED ===\n", total_fail );
  }

  return total_fail > 0 ? 1 : 0;
}

#else /* !AT_HAS_AVX512_GENERAL */

int main( void ) {
  printf( "AVX-512F General tests skipped (not compiled with AVX-512F support)\n" );
  printf( "Compile with -DAT_HAS_AVX512=1 -DAT_HAS_AVX512_GENERAL=1 to enable\n" );
  return 0;
}

#endif /* AT_HAS_AVX512_GENERAL */
