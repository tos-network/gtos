/* AVX-512F General Field Arithmetic Tests and Benchmarks
   Tests AVX-512F optimized implementations for correctness and performance. */

#include "at/crypto/at_crypto_base.h"
#include "at/infra/rng/at_rng.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#if AT_HAS_AVX512_GENERAL

/* Include AVX-512F General implementation */
#include "at_f25519.h"
#include "at_r2526x8.h"

/* ========================================================================
   Test Utilities
   ======================================================================== */

static void
print_hex( uchar const * data, ulong sz ) {
  for( ulong i = 0; i < sz; i++ ) {
    printf( "%02x", data[i] );
  }
}

static int
bytes_eq( uchar const * a, uchar const * b, ulong sz ) {
  for( ulong i = 0; i < sz; i++ ) {
    if( a[i] != b[i] ) return 0;
  }
  return 1;
}

/* Generate random bytes */
static void
random_bytes( uchar * out, ulong sz, at_rng_t * rng ) {
  for( ulong i = 0; i < sz; i++ ) {
    out[i] = (uchar)at_rng_uint( rng );
  }
}

/* ========================================================================
   Field Arithmetic Tests - Self-consistency
   ======================================================================== */

/* Test: a * b = b * a (commutativity) */
static int
test_mul_commutative( at_rng_t * rng, int iterations ) {
  int fail = 0;

  printf( "Testing multiplication commutativity (%d iterations)...\n", iterations );

  for( int i = 0; i < iterations; i++ ) {
    uchar a_bytes[32], b_bytes[32];
    random_bytes( a_bytes, 32, rng );
    random_bytes( b_bytes, 32, rng );
    a_bytes[31] &= 0x7F;
    b_bytes[31] &= 0x7F;

    at_f25519_t a, b, ab, ba;
    at_f25519_frombytes( &a, a_bytes );
    at_f25519_frombytes( &b, b_bytes );

    at_f25519_mul( &ab, &a, &b );
    at_f25519_mul( &ba, &b, &a );

    uchar ab_out[32], ba_out[32];
    at_f25519_tobytes( ab_out, &ab );
    at_f25519_tobytes( ba_out, &ba );

    if( !bytes_eq( ab_out, ba_out, 32 ) ) {
      printf( "FAIL: mul_commutative iteration %d\n", i );
      printf( "  a:   " ); print_hex( a_bytes, 32 ); printf( "\n" );
      printf( "  b:   " ); print_hex( b_bytes, 32 ); printf( "\n" );
      printf( "  a*b: " ); print_hex( ab_out, 32 ); printf( "\n" );
      printf( "  b*a: " ); print_hex( ba_out, 32 ); printf( "\n" );
      fail++;
      if( fail >= 5 ) break;
    }
  }

  if( fail == 0 ) {
    printf( "PASS: mul_commutative (%d iterations)\n", iterations );
  }
  return fail;
}

/* Test: a * 1 = a (identity) */
static int
test_mul_identity( at_rng_t * rng, int iterations ) {
  int fail = 0;

  printf( "Testing multiplication identity (%d iterations)...\n", iterations );

  for( int i = 0; i < iterations; i++ ) {
    uchar a_bytes[32];
    random_bytes( a_bytes, 32, rng );
    a_bytes[31] &= 0x7F;

    at_f25519_t a, r;
    at_f25519_frombytes( &a, a_bytes );
    at_f25519_mul( &r, &a, at_f25519_one );

    uchar a_out[32], r_out[32];
    at_f25519_tobytes( a_out, &a );
    at_f25519_tobytes( r_out, &r );

    if( !bytes_eq( a_out, r_out, 32 ) ) {
      printf( "FAIL: mul_identity iteration %d\n", i );
      fail++;
      if( fail >= 5 ) break;
    }
  }

  if( fail == 0 ) {
    printf( "PASS: mul_identity (%d iterations)\n", iterations );
  }
  return fail;
}

/* Test: a * a = sqr(a) */
static int
test_sqr_vs_mul( at_rng_t * rng, int iterations ) {
  int fail = 0;

  printf( "Testing sqr vs mul (%d iterations)...\n", iterations );

  for( int i = 0; i < iterations; i++ ) {
    uchar a_bytes[32];
    random_bytes( a_bytes, 32, rng );
    a_bytes[31] &= 0x7F;

    at_f25519_t a, mul_r, sqr_r;
    at_f25519_frombytes( &a, a_bytes );

    at_f25519_mul( &mul_r, &a, &a );
    at_f25519_sqr( &sqr_r, &a );

    uchar mul_out[32], sqr_out[32];
    at_f25519_tobytes( mul_out, &mul_r );
    at_f25519_tobytes( sqr_out, &sqr_r );

    if( !bytes_eq( mul_out, sqr_out, 32 ) ) {
      printf( "FAIL: sqr_vs_mul iteration %d\n", i );
      printf( "  a:   " ); print_hex( a_bytes, 32 ); printf( "\n" );
      printf( "  a*a: " ); print_hex( mul_out, 32 ); printf( "\n" );
      printf( "  sqr: " ); print_hex( sqr_out, 32 ); printf( "\n" );
      fail++;
      if( fail >= 5 ) break;
    }
  }

  if( fail == 0 ) {
    printf( "PASS: sqr_vs_mul (%d iterations)\n", iterations );
  }
  return fail;
}

/* Test: (a + b) - b = a */
static int
test_add_sub_inverse( at_rng_t * rng, int iterations ) {
  int fail = 0;

  printf( "Testing add/sub inverse (%d iterations)...\n", iterations );

  for( int i = 0; i < iterations; i++ ) {
    uchar a_bytes[32], b_bytes[32];
    random_bytes( a_bytes, 32, rng );
    random_bytes( b_bytes, 32, rng );
    a_bytes[31] &= 0x7F;
    b_bytes[31] &= 0x7F;

    at_f25519_t a, b, sum, result;
    at_f25519_frombytes( &a, a_bytes );
    at_f25519_frombytes( &b, b_bytes );

    at_f25519_add( &sum, &a, &b );
    at_f25519_sub( &result, &sum, &b );

    uchar a_out[32], r_out[32];
    at_f25519_tobytes( a_out, &a );
    at_f25519_tobytes( r_out, &result );

    if( !bytes_eq( a_out, r_out, 32 ) ) {
      printf( "FAIL: add_sub_inverse iteration %d\n", i );
      fail++;
      if( fail >= 5 ) break;
    }
  }

  if( fail == 0 ) {
    printf( "PASS: add_sub_inverse (%d iterations)\n", iterations );
  }
  return fail;
}

/* Test: a + 0 = a */
static int
test_add_zero( at_rng_t * rng, int iterations ) {
  int fail = 0;

  printf( "Testing add zero (%d iterations)...\n", iterations );

  for( int i = 0; i < iterations; i++ ) {
    uchar a_bytes[32];
    random_bytes( a_bytes, 32, rng );
    a_bytes[31] &= 0x7F;

    at_f25519_t a, r;
    at_f25519_frombytes( &a, a_bytes );
    at_f25519_add( &r, &a, at_f25519_zero );

    uchar a_out[32], r_out[32];
    at_f25519_tobytes( a_out, &a );
    at_f25519_tobytes( r_out, &r );

    if( !bytes_eq( a_out, r_out, 32 ) ) {
      printf( "FAIL: add_zero iteration %d\n", i );
      fail++;
      if( fail >= 5 ) break;
    }
  }

  if( fail == 0 ) {
    printf( "PASS: add_zero (%d iterations)\n", iterations );
  }
  return fail;
}

/* Test: a + (-a) = 0 */
static int
test_neg_inverse( at_rng_t * rng, int iterations ) {
  int fail = 0;

  printf( "Testing neg inverse (a + (-a) = 0) (%d iterations)...\n", iterations );

  for( int i = 0; i < iterations; i++ ) {
    uchar a_bytes[32];
    random_bytes( a_bytes, 32, rng );
    a_bytes[31] &= 0x7F;

    at_f25519_t a, neg_a, sum;
    at_f25519_frombytes( &a, a_bytes );
    at_f25519_neg( &neg_a, &a );
    at_f25519_carry( &neg_a );
    at_f25519_add( &sum, &a, &neg_a );

    if( !at_f25519_is_zero( &sum ) ) {
      printf( "FAIL: neg_inverse iteration %d\n", i );
      uchar sum_out[32];
      at_f25519_tobytes( sum_out, &sum );
      printf( "  a: " ); print_hex( a_bytes, 32 ); printf( "\n" );
      printf( "  a+(-a): " ); print_hex( sum_out, 32 ); printf( "\n" );
      fail++;
      if( fail >= 5 ) break;
    }
  }

  if( fail == 0 ) {
    printf( "PASS: neg_inverse (%d iterations)\n", iterations );
  }
  return fail;
}

/* Test: frombytes -> tobytes round-trip */
static int
test_roundtrip( at_rng_t * rng, int iterations ) {
  int fail = 0;

  printf( "Testing frombytes/tobytes roundtrip (%d iterations)...\n", iterations );

  for( int i = 0; i < iterations; i++ ) {
    uchar in_bytes[32], out_bytes[32];
    random_bytes( in_bytes, 32, rng );
    /* Clear high bit to ensure canonical */
    in_bytes[31] &= 0x7F;

    at_f25519_t a;
    at_f25519_frombytes( &a, in_bytes );
    at_f25519_tobytes( out_bytes, &a );

    /* Result should be equivalent mod p */
    at_f25519_t b;
    at_f25519_frombytes( &b, out_bytes );

    uchar final[32];
    at_f25519_tobytes( final, &b );

    if( !bytes_eq( out_bytes, final, 32 ) ) {
      printf( "FAIL: roundtrip iteration %d\n", i );
      fail++;
      if( fail >= 5 ) break;
    }
  }

  if( fail == 0 ) {
    printf( "PASS: roundtrip (%d iterations)\n", iterations );
  }
  return fail;
}

/* Test: (a * b) * c = a * (b * c) (associativity) */
static int
test_mul_associative( at_rng_t * rng, int iterations ) {
  int fail = 0;

  printf( "Testing multiplication associativity (%d iterations)...\n", iterations );

  for( int i = 0; i < iterations; i++ ) {
    uchar a_bytes[32], b_bytes[32], c_bytes[32];
    random_bytes( a_bytes, 32, rng );
    random_bytes( b_bytes, 32, rng );
    random_bytes( c_bytes, 32, rng );
    a_bytes[31] &= 0x7F;
    b_bytes[31] &= 0x7F;
    c_bytes[31] &= 0x7F;

    at_f25519_t a, b, c, ab, ab_c, bc, a_bc;
    at_f25519_frombytes( &a, a_bytes );
    at_f25519_frombytes( &b, b_bytes );
    at_f25519_frombytes( &c, c_bytes );

    /* (a * b) * c */
    at_f25519_mul( &ab, &a, &b );
    at_f25519_mul( &ab_c, &ab, &c );

    /* a * (b * c) */
    at_f25519_mul( &bc, &b, &c );
    at_f25519_mul( &a_bc, &a, &bc );

    uchar ab_c_out[32], a_bc_out[32];
    at_f25519_tobytes( ab_c_out, &ab_c );
    at_f25519_tobytes( a_bc_out, &a_bc );

    if( !bytes_eq( ab_c_out, a_bc_out, 32 ) ) {
      printf( "FAIL: mul_associative iteration %d\n", i );
      fail++;
      if( fail >= 5 ) break;
    }
  }

  if( fail == 0 ) {
    printf( "PASS: mul_associative (%d iterations)\n", iterations );
  }
  return fail;
}

/* Test: mul8 produces same results as 8 individual muls */
static int
test_mul8_consistency( at_rng_t * rng, int iterations ) {
  int fail = 0;

  printf( "Testing mul8 consistency (%d iterations)...\n", iterations );

  for( int i = 0; i < iterations; i++ ) {
    uchar a_bytes[8][32], b_bytes[8][32];
    for( int j = 0; j < 8; j++ ) {
      random_bytes( a_bytes[j], 32, rng );
      random_bytes( b_bytes[j], 32, rng );
      a_bytes[j][31] &= 0x7F;
      b_bytes[j][31] &= 0x7F;
    }

    at_f25519_t fa[8], fb[8];
    for( int j = 0; j < 8; j++ ) {
      at_f25519_frombytes( &fa[j], a_bytes[j] );
      at_f25519_frombytes( &fb[j], b_bytes[j] );
    }

    /* Compute with individual muls */
    at_f25519_t s[8];
    for( int j = 0; j < 8; j++ ) {
      at_f25519_mul( &s[j], &fa[j], &fb[j] );
    }

    /* Compute with mul8 */
    at_f25519_t p[8];
    at_f25519_mul8( &p[0], &fa[0], &fb[0],
                    &p[1], &fa[1], &fb[1],
                    &p[2], &fa[2], &fb[2],
                    &p[3], &fa[3], &fb[3],
                    &p[4], &fa[4], &fb[4],
                    &p[5], &fa[5], &fb[5],
                    &p[6], &fa[6], &fb[6],
                    &p[7], &fa[7], &fb[7] );

    /* Compare */
    int mismatch = 0;
    for( int j = 0; j < 8; j++ ) {
      uchar ss[32], pp[32];
      at_f25519_tobytes( ss, &s[j] );
      at_f25519_tobytes( pp, &p[j] );
      if( !bytes_eq( ss, pp, 32 ) ) {
        mismatch = 1;
        break;
      }
    }

    if( mismatch ) {
      printf( "FAIL: mul8_consistency iteration %d\n", i );
      fail++;
      if( fail >= 5 ) break;
    }
  }

  if( fail == 0 ) {
    printf( "PASS: mul8_consistency (%d iterations)\n", iterations );
  }
  return fail;
}

/* Test: sqr8 produces same results as 8 individual sqrs */
static int
test_sqr8_consistency( at_rng_t * rng, int iterations ) {
  int fail = 0;

  printf( "Testing sqr8 consistency (%d iterations)...\n", iterations );

  for( int i = 0; i < iterations; i++ ) {
    uchar a_bytes[8][32];
    for( int j = 0; j < 8; j++ ) {
      random_bytes( a_bytes[j], 32, rng );
      a_bytes[j][31] &= 0x7F;
    }

    at_f25519_t fa[8];
    for( int j = 0; j < 8; j++ ) {
      at_f25519_frombytes( &fa[j], a_bytes[j] );
    }

    /* Compute with individual sqrs */
    at_f25519_t s[8];
    for( int j = 0; j < 8; j++ ) {
      at_f25519_sqr( &s[j], &fa[j] );
    }

    /* Compute with sqr8 */
    at_f25519_t p[8];
    at_f25519_sqr8( &p[0], &fa[0],
                    &p[1], &fa[1],
                    &p[2], &fa[2],
                    &p[3], &fa[3],
                    &p[4], &fa[4],
                    &p[5], &fa[5],
                    &p[6], &fa[6],
                    &p[7], &fa[7] );

    /* Compare */
    int mismatch = 0;
    for( int j = 0; j < 8; j++ ) {
      uchar ss[32], pp[32];
      at_f25519_tobytes( ss, &s[j] );
      at_f25519_tobytes( pp, &p[j] );
      if( !bytes_eq( ss, pp, 32 ) ) {
        mismatch = 1;
        break;
      }
    }

    if( mismatch ) {
      printf( "FAIL: sqr8_consistency iteration %d\n", i );
      fail++;
      if( fail >= 5 ) break;
    }
  }

  if( fail == 0 ) {
    printf( "PASS: sqr8_consistency (%d iterations)\n", iterations );
  }
  return fail;
}

/* Test: mul4 produces same results as 4 individual muls */
static int
test_mul4_consistency( at_rng_t * rng, int iterations ) {
  int fail = 0;

  printf( "Testing mul4 consistency (%d iterations)...\n", iterations );

  for( int i = 0; i < iterations; i++ ) {
    uchar a_bytes[4][32], b_bytes[4][32];
    for( int j = 0; j < 4; j++ ) {
      random_bytes( a_bytes[j], 32, rng );
      random_bytes( b_bytes[j], 32, rng );
      a_bytes[j][31] &= 0x7F;
      b_bytes[j][31] &= 0x7F;
    }

    at_f25519_t fa[4], fb[4];
    for( int j = 0; j < 4; j++ ) {
      at_f25519_frombytes( &fa[j], a_bytes[j] );
      at_f25519_frombytes( &fb[j], b_bytes[j] );
    }

    /* Compute with individual muls */
    at_f25519_t s[4];
    for( int j = 0; j < 4; j++ ) {
      at_f25519_mul( &s[j], &fa[j], &fb[j] );
    }

    /* Compute with mul4 */
    at_f25519_t p[4];
    at_f25519_mul4( &p[0], &fa[0], &fb[0],
                    &p[1], &fa[1], &fb[1],
                    &p[2], &fa[2], &fb[2],
                    &p[3], &fa[3], &fb[3] );

    /* Compare */
    int mismatch = 0;
    for( int j = 0; j < 4; j++ ) {
      uchar ss[32], pp[32];
      at_f25519_tobytes( ss, &s[j] );
      at_f25519_tobytes( pp, &p[j] );
      if( !bytes_eq( ss, pp, 32 ) ) {
        mismatch = 1;
        break;
      }
    }

    if( mismatch ) {
      printf( "FAIL: mul4_consistency iteration %d\n", i );
      fail++;
      if( fail >= 5 ) break;
    }
  }

  if( fail == 0 ) {
    printf( "PASS: mul4_consistency (%d iterations)\n", iterations );
  }
  return fail;
}

/* Test: sqr4 produces same results as 4 individual sqrs */
static int
test_sqr4_consistency( at_rng_t * rng, int iterations ) {
  int fail = 0;

  printf( "Testing sqr4 consistency (%d iterations)...\n", iterations );

  for( int i = 0; i < iterations; i++ ) {
    uchar a_bytes[4][32];
    for( int j = 0; j < 4; j++ ) {
      random_bytes( a_bytes[j], 32, rng );
      a_bytes[j][31] &= 0x7F;
    }

    at_f25519_t fa[4];
    for( int j = 0; j < 4; j++ ) {
      at_f25519_frombytes( &fa[j], a_bytes[j] );
    }

    /* Compute with individual sqrs */
    at_f25519_t s[4];
    for( int j = 0; j < 4; j++ ) {
      at_f25519_sqr( &s[j], &fa[j] );
    }

    /* Compute with sqr4 */
    at_f25519_t p[4];
    at_f25519_sqr4( &p[0], &fa[0],
                    &p[1], &fa[1],
                    &p[2], &fa[2],
                    &p[3], &fa[3] );

    /* Compare */
    int mismatch = 0;
    for( int j = 0; j < 4; j++ ) {
      uchar ss[32], pp[32];
      at_f25519_tobytes( ss, &s[j] );
      at_f25519_tobytes( pp, &p[j] );
      if( !bytes_eq( ss, pp, 32 ) ) {
        mismatch = 1;
        break;
      }
    }

    if( mismatch ) {
      printf( "FAIL: sqr4_consistency iteration %d\n", i );
      fail++;
      if( fail >= 5 ) break;
    }
  }

  if( fail == 0 ) {
    printf( "PASS: sqr4_consistency (%d iterations)\n", iterations );
  }
  return fail;
}

/* ========================================================================
   Performance Benchmarks
   ======================================================================== */

static double
get_time_sec( void ) {
  struct timespec ts;
  clock_gettime( CLOCK_MONOTONIC, &ts );
  return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void
benchmark_mul( int iterations ) {
  at_f25519_t a, b, r;
  uchar bytes[32] = { 0x42 };
  at_f25519_frombytes( &a, bytes );
  bytes[0] = 0x23;
  at_f25519_frombytes( &b, bytes );

  /* Warmup */
  for( int i = 0; i < 10000; i++ ) {
    at_f25519_mul( &r, &a, &b );
  }

  double start = get_time_sec();
  for( int i = 0; i < iterations; i++ ) {
    at_f25519_mul( &r, &a, &b );
  }
  double end = get_time_sec();

  double ops_per_sec = iterations / (end - start);
  printf( "AVX512 scalar mul:    %12.0f ops/sec  (%6.2f ns/op)\n",
          ops_per_sec, (end - start) * 1e9 / iterations );
}

static void
benchmark_mul8( int iterations ) {
  at_f25519_t a[8], b[8], r[8];

  uchar bytes[32] = { 0x42 };
  for( int i = 0; i < 8; i++ ) {
    bytes[0] = (uchar)(0x42 + i);
    at_f25519_frombytes( &a[i], bytes );
    bytes[0] = (uchar)(0x23 + i);
    at_f25519_frombytes( &b[i], bytes );
  }

  /* Warmup */
  for( int i = 0; i < 10000; i++ ) {
    at_f25519_mul8( &r[0], &a[0], &b[0],
                    &r[1], &a[1], &b[1],
                    &r[2], &a[2], &b[2],
                    &r[3], &a[3], &b[3],
                    &r[4], &a[4], &b[4],
                    &r[5], &a[5], &b[5],
                    &r[6], &a[6], &b[6],
                    &r[7], &a[7], &b[7] );
  }

  double start = get_time_sec();
  for( int i = 0; i < iterations; i++ ) {
    at_f25519_mul8( &r[0], &a[0], &b[0],
                    &r[1], &a[1], &b[1],
                    &r[2], &a[2], &b[2],
                    &r[3], &a[3], &b[3],
                    &r[4], &a[4], &b[4],
                    &r[5], &a[5], &b[5],
                    &r[6], &a[6], &b[6],
                    &r[7], &a[7], &b[7] );
  }
  double end = get_time_sec();

  double ops_per_sec = (iterations * 8.0) / (end - start);
  printf( "AVX512 SIMD mul8:     %12.0f ops/sec  (%6.2f ns/op)\n",
          ops_per_sec, (end - start) * 1e9 / (iterations * 8) );
}

static void
benchmark_mul4( int iterations ) {
  at_f25519_t a[4], b[4], r[4];

  uchar bytes[32] = { 0x42 };
  for( int i = 0; i < 4; i++ ) {
    bytes[0] = (uchar)(0x42 + i);
    at_f25519_frombytes( &a[i], bytes );
    bytes[0] = (uchar)(0x23 + i);
    at_f25519_frombytes( &b[i], bytes );
  }

  /* Warmup */
  for( int i = 0; i < 10000; i++ ) {
    at_f25519_mul4( &r[0], &a[0], &b[0],
                    &r[1], &a[1], &b[1],
                    &r[2], &a[2], &b[2],
                    &r[3], &a[3], &b[3] );
  }

  double start = get_time_sec();
  for( int i = 0; i < iterations; i++ ) {
    at_f25519_mul4( &r[0], &a[0], &b[0],
                    &r[1], &a[1], &b[1],
                    &r[2], &a[2], &b[2],
                    &r[3], &a[3], &b[3] );
  }
  double end = get_time_sec();

  double ops_per_sec = (iterations * 4.0) / (end - start);
  printf( "AVX512 SIMD mul4:     %12.0f ops/sec  (%6.2f ns/op)\n",
          ops_per_sec, (end - start) * 1e9 / (iterations * 4) );
}

static void
benchmark_sqr( int iterations ) {
  at_f25519_t a, r;
  uchar bytes[32] = { 0x42 };
  at_f25519_frombytes( &a, bytes );

  /* Warmup */
  for( int i = 0; i < 10000; i++ ) {
    at_f25519_sqr( &r, &a );
  }

  double start = get_time_sec();
  for( int i = 0; i < iterations; i++ ) {
    at_f25519_sqr( &r, &a );
  }
  double end = get_time_sec();

  double ops_per_sec = iterations / (end - start);
  printf( "AVX512 scalar sqr:    %12.0f ops/sec  (%6.2f ns/op)\n",
          ops_per_sec, (end - start) * 1e9 / iterations );
}

static void
benchmark_sqr8( int iterations ) {
  at_f25519_t a[8], r[8];

  uchar bytes[32] = { 0x42 };
  for( int i = 0; i < 8; i++ ) {
    bytes[0] = (uchar)(0x42 + i);
    at_f25519_frombytes( &a[i], bytes );
  }

  /* Warmup */
  for( int i = 0; i < 10000; i++ ) {
    at_f25519_sqr8( &r[0], &a[0],
                    &r[1], &a[1],
                    &r[2], &a[2],
                    &r[3], &a[3],
                    &r[4], &a[4],
                    &r[5], &a[5],
                    &r[6], &a[6],
                    &r[7], &a[7] );
  }

  double start = get_time_sec();
  for( int i = 0; i < iterations; i++ ) {
    at_f25519_sqr8( &r[0], &a[0],
                    &r[1], &a[1],
                    &r[2], &a[2],
                    &r[3], &a[3],
                    &r[4], &a[4],
                    &r[5], &a[5],
                    &r[6], &a[6],
                    &r[7], &a[7] );
  }
  double end = get_time_sec();

  double ops_per_sec = (iterations * 8.0) / (end - start);
  printf( "AVX512 SIMD sqr8:     %12.0f ops/sec  (%6.2f ns/op)\n",
          ops_per_sec, (end - start) * 1e9 / (iterations * 8) );
}

static void
benchmark_sqr4( int iterations ) {
  at_f25519_t a[4], r[4];

  uchar bytes[32] = { 0x42 };
  for( int i = 0; i < 4; i++ ) {
    bytes[0] = (uchar)(0x42 + i);
    at_f25519_frombytes( &a[i], bytes );
  }

  /* Warmup */
  for( int i = 0; i < 10000; i++ ) {
    at_f25519_sqr4( &r[0], &a[0],
                    &r[1], &a[1],
                    &r[2], &a[2],
                    &r[3], &a[3] );
  }

  double start = get_time_sec();
  for( int i = 0; i < iterations; i++ ) {
    at_f25519_sqr4( &r[0], &a[0],
                    &r[1], &a[1],
                    &r[2], &a[2],
                    &r[3], &a[3] );
  }
  double end = get_time_sec();

  double ops_per_sec = (iterations * 4.0) / (end - start);
  printf( "AVX512 SIMD sqr4:     %12.0f ops/sec  (%6.2f ns/op)\n",
          ops_per_sec, (end - start) * 1e9 / (iterations * 4) );
}

/* ========================================================================
   Main
   ======================================================================== */

int main( void ) {
  int fail = 0;

  /* Initialize RNG */
  at_rng_t rng_mem[1];
  at_rng_t * rng = at_rng_join( at_rng_new( rng_mem, 12345UL, 0UL ) );

  printf( "=== AVX-512F General Field Arithmetic Tests ===\n\n" );

  /* Self-consistency tests */
  fail += test_mul_commutative( rng, 10000 );
  fail += test_mul_identity( rng, 10000 );
  fail += test_mul_associative( rng, 5000 );
  fail += test_sqr_vs_mul( rng, 10000 );
  fail += test_add_sub_inverse( rng, 10000 );
  fail += test_add_zero( rng, 10000 );
  fail += test_neg_inverse( rng, 10000 );
  fail += test_roundtrip( rng, 10000 );
  fail += test_mul8_consistency( rng, 1000 );
  fail += test_sqr8_consistency( rng, 1000 );
  fail += test_mul4_consistency( rng, 1000 );
  fail += test_sqr4_consistency( rng, 1000 );

  printf( "\n=== Performance Benchmarks ===\n\n" );

  int bench_iters = 1000000;

  benchmark_mul( bench_iters );
  benchmark_sqr( bench_iters );
  benchmark_mul8( bench_iters / 8 );
  benchmark_sqr8( bench_iters / 8 );
  benchmark_mul4( bench_iters / 4 );
  benchmark_sqr4( bench_iters / 4 );

  printf( "\n" );

  at_rng_delete( at_rng_leave( rng ) );

  printf( "Total: %d failures\n", fail );
  return fail ? 1 : 0;
}

#else /* !AT_HAS_AVX512_GENERAL */

int main( void ) {
  printf( "AVX-512F General tests skipped (not compiled with AVX-512F support)\n" );
  printf( "Compile with -DAT_HAS_AVX512=1 -DAT_HAS_AVX512_GENERAL=1 to enable\n" );
  return 0;
}

#endif
