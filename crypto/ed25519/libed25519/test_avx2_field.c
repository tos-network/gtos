/* AVX2 Field Arithmetic Tests and Benchmarks
   Tests AVX2 optimized implementations for correctness and performance. */

#include "at/crypto/at_crypto_base.h"
#include "at/infra/rng/at_rng.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#if AT_HAS_AVX && !AT_HAS_AVX512_IFMA

/* Include AVX2 implementation */
#include "avx2/at_f25519.h"
#include "avx2/at_curve25519.h"

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

/* Test: mul4 produces same results as 4 individual muls */
static int
test_mul4_consistency( at_rng_t * rng, int iterations ) {
  int fail = 0;

  printf( "Testing mul4 consistency (%d iterations)...\n", iterations );

  for( int i = 0; i < iterations; i++ ) {
    uchar a1[32], a2[32], a3[32], a4[32];
    uchar b1[32], b2[32], b3[32], b4[32];

    random_bytes( a1, 32, rng );
    random_bytes( a2, 32, rng );
    random_bytes( a3, 32, rng );
    random_bytes( a4, 32, rng );
    random_bytes( b1, 32, rng );
    random_bytes( b2, 32, rng );
    random_bytes( b3, 32, rng );
    random_bytes( b4, 32, rng );

    at_f25519_t fa1, fa2, fa3, fa4;
    at_f25519_t fb1, fb2, fb3, fb4;

    at_f25519_frombytes( &fa1, a1 );
    at_f25519_frombytes( &fa2, a2 );
    at_f25519_frombytes( &fa3, a3 );
    at_f25519_frombytes( &fa4, a4 );
    at_f25519_frombytes( &fb1, b1 );
    at_f25519_frombytes( &fb2, b2 );
    at_f25519_frombytes( &fb3, b3 );
    at_f25519_frombytes( &fb4, b4 );

    /* Compute with individual muls */
    at_f25519_t s1, s2, s3, s4;
    at_f25519_mul( &s1, &fa1, &fb1 );
    at_f25519_mul( &s2, &fa2, &fb2 );
    at_f25519_mul( &s3, &fa3, &fb3 );
    at_f25519_mul( &s4, &fa4, &fb4 );

    /* Compute with mul4 */
    at_f25519_t p1, p2, p3, p4;
    at_f25519_mul4( &p1, &fa1, &fb1,
                    &p2, &fa2, &fb2,
                    &p3, &fa3, &fb3,
                    &p4, &fa4, &fb4 );

    /* Compare */
    uchar ss1[32], ss2[32], ss3[32], ss4[32];
    uchar pp1[32], pp2[32], pp3[32], pp4[32];

    at_f25519_tobytes( ss1, &s1 );
    at_f25519_tobytes( ss2, &s2 );
    at_f25519_tobytes( ss3, &s3 );
    at_f25519_tobytes( ss4, &s4 );
    at_f25519_tobytes( pp1, &p1 );
    at_f25519_tobytes( pp2, &p2 );
    at_f25519_tobytes( pp3, &p3 );
    at_f25519_tobytes( pp4, &p4 );

    if( !bytes_eq( ss1, pp1, 32 ) || !bytes_eq( ss2, pp2, 32 ) ||
        !bytes_eq( ss3, pp3, 32 ) || !bytes_eq( ss4, pp4, 32 ) ) {
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
    uchar a1[32], a2[32], a3[32], a4[32];

    random_bytes( a1, 32, rng );
    random_bytes( a2, 32, rng );
    random_bytes( a3, 32, rng );
    random_bytes( a4, 32, rng );

    at_f25519_t fa1, fa2, fa3, fa4;
    at_f25519_frombytes( &fa1, a1 );
    at_f25519_frombytes( &fa2, a2 );
    at_f25519_frombytes( &fa3, a3 );
    at_f25519_frombytes( &fa4, a4 );

    /* Compute with individual sqrs */
    at_f25519_t s1, s2, s3, s4;
    at_f25519_sqr( &s1, &fa1 );
    at_f25519_sqr( &s2, &fa2 );
    at_f25519_sqr( &s3, &fa3 );
    at_f25519_sqr( &s4, &fa4 );

    /* Compute with sqr4 */
    at_f25519_t p1, p2, p3, p4;
    at_f25519_sqr4( &p1, &fa1,
                    &p2, &fa2,
                    &p3, &fa3,
                    &p4, &fa4 );

    /* Compare */
    uchar ss1[32], ss2[32], ss3[32], ss4[32];
    uchar pp1[32], pp2[32], pp3[32], pp4[32];

    at_f25519_tobytes( ss1, &s1 );
    at_f25519_tobytes( ss2, &s2 );
    at_f25519_tobytes( ss3, &s3 );
    at_f25519_tobytes( ss4, &s4 );
    at_f25519_tobytes( pp1, &p1 );
    at_f25519_tobytes( pp2, &p2 );
    at_f25519_tobytes( pp3, &p3 );
    at_f25519_tobytes( pp4, &p4 );

    if( !bytes_eq( ss1, pp1, 32 ) || !bytes_eq( ss2, pp2, 32 ) ||
        !bytes_eq( ss3, pp3, 32 ) || !bytes_eq( ss4, pp4, 32 ) ) {
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
  printf( "AVX2 scalar mul:    %12.0f ops/sec  (%6.2f ns/op)\n",
          ops_per_sec, (end - start) * 1e9 / iterations );
}

static void
benchmark_mul4( int iterations ) {
  at_f25519_t a1, a2, a3, a4, b1, b2, b3, b4;
  at_f25519_t r1, r2, r3, r4;

  uchar bytes[32] = { 0x42 };
  at_f25519_frombytes( &a1, bytes ); bytes[0]++;
  at_f25519_frombytes( &a2, bytes ); bytes[0]++;
  at_f25519_frombytes( &a3, bytes ); bytes[0]++;
  at_f25519_frombytes( &a4, bytes ); bytes[0]++;
  at_f25519_frombytes( &b1, bytes ); bytes[0]++;
  at_f25519_frombytes( &b2, bytes ); bytes[0]++;
  at_f25519_frombytes( &b3, bytes ); bytes[0]++;
  at_f25519_frombytes( &b4, bytes );

  /* Warmup */
  for( int i = 0; i < 10000; i++ ) {
    at_f25519_mul4( &r1, &a1, &b1, &r2, &a2, &b2,
                    &r3, &a3, &b3, &r4, &a4, &b4 );
  }

  double start = get_time_sec();
  for( int i = 0; i < iterations; i++ ) {
    at_f25519_mul4( &r1, &a1, &b1, &r2, &a2, &b2,
                    &r3, &a3, &b3, &r4, &a4, &b4 );
  }
  double end = get_time_sec();

  double ops_per_sec = (iterations * 4.0) / (end - start);
  printf( "AVX2 SIMD mul4:     %12.0f ops/sec  (%6.2f ns/op)\n",
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
  printf( "AVX2 scalar sqr:    %12.0f ops/sec  (%6.2f ns/op)\n",
          ops_per_sec, (end - start) * 1e9 / iterations );
}

static void
benchmark_sqr4( int iterations ) {
  at_f25519_t a1, a2, a3, a4;
  at_f25519_t r1, r2, r3, r4;

  uchar bytes[32] = { 0x42 };
  at_f25519_frombytes( &a1, bytes ); bytes[0]++;
  at_f25519_frombytes( &a2, bytes ); bytes[0]++;
  at_f25519_frombytes( &a3, bytes ); bytes[0]++;
  at_f25519_frombytes( &a4, bytes );

  /* Warmup */
  for( int i = 0; i < 10000; i++ ) {
    at_f25519_sqr4( &r1, &a1, &r2, &a2, &r3, &a3, &r4, &a4 );
  }

  double start = get_time_sec();
  for( int i = 0; i < iterations; i++ ) {
    at_f25519_sqr4( &r1, &a1, &r2, &a2, &r3, &a3, &r4, &a4 );
  }
  double end = get_time_sec();

  double ops_per_sec = (iterations * 4.0) / (end - start);
  printf( "AVX2 SIMD sqr4:     %12.0f ops/sec  (%6.2f ns/op)\n",
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

  /* Initialize AVX2 constants */
  at_ed25519_avx2_init_constants();

  printf( "=== AVX2 Field Arithmetic Tests ===\n\n" );

  /* Self-consistency tests */
  fail += test_mul_commutative( rng, 10000 );
  fail += test_mul_identity( rng, 10000 );
  fail += test_sqr_vs_mul( rng, 10000 );
  fail += test_add_sub_inverse( rng, 10000 );
  fail += test_add_zero( rng, 10000 );
  fail += test_roundtrip( rng, 10000 );
  fail += test_mul4_consistency( rng, 1000 );
  fail += test_sqr4_consistency( rng, 1000 );

  printf( "\n=== Performance Benchmarks ===\n\n" );

  int bench_iters = 1000000;

  benchmark_mul( bench_iters );
  benchmark_sqr( bench_iters );
  benchmark_mul4( bench_iters / 4 );
  benchmark_sqr4( bench_iters / 4 );

  printf( "\n" );

  at_rng_delete( at_rng_leave( rng ) );

  printf( "Total: %d failures\n", fail );
  return fail ? 1 : 0;
}

#else /* !AT_HAS_AVX || AT_HAS_AVX512_IFMA */

int main( void ) {
  printf( "AVX2 tests skipped (not compiled with AVX2 support or using AVX512_IFMA)\n" );
  return 0;
}

#endif
