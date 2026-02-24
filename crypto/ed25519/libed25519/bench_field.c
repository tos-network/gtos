/* Field Arithmetic Benchmark - AVX2 vs Reference
   Compile with:
     Reference: cc -O2 -march=native -D_GNU_SOURCE -Iinclude -Isrc bench_field.c -o bench_ref -lm
     AVX2: cc -O2 -march=native -D_GNU_SOURCE -DAT_HAS_AVX=1 -DAT_HAS_AVX512_IFMA=0 -Iinclude -Isrc bench_field.c libat_crypto.a libat_util.a -o bench_avx2 -lm
*/

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define _GNU_SOURCE
#include <time.h>

/* Include appropriate implementation */
#if AT_HAS_AVX && !AT_HAS_AVX512_IFMA
  #define BENCH_NAME "AVX2"
  #include "avx2/at_f25519.h"
#else
  #define BENCH_NAME "Reference (fiat-crypto)"
  #include "at/crypto/at_f25519.h"
#endif

static double
get_time_sec( void ) {
  struct timespec ts;
  clock_gettime( CLOCK_MONOTONIC, &ts );
  return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* Number of limbs differs: AVX2 uses 10 limbs, reference uses 5 */
#if AT_HAS_AVX && !AT_HAS_AVX512_IFMA
  #define NUM_LIMBS 10
#else
  #define NUM_LIMBS 5
#endif

/* Benchmark field multiplication */
static void
bench_mul( int iterations ) {
  at_f25519_t a, b, r;

  /* Initialize with non-zero values */
  for( int i = 0; i < NUM_LIMBS; i++ ) {
    a.el[i] = 0x123456789ABCULL + i;
    b.el[i] = 0xFEDCBA987654ULL + i;
  }

  /* Warmup */
  for( int i = 0; i < 1000; i++ ) {
    at_f25519_mul( &r, &a, &b );
    a = r;
  }

  double start = get_time_sec();
  for( int i = 0; i < iterations; i++ ) {
    at_f25519_mul( &r, &a, &b );
    a = r;  /* Prevent optimization */
  }
  double end = get_time_sec();

  double elapsed = end - start;
  double ops_per_sec = (double)iterations / elapsed;
  double ns_per_op = elapsed * 1e9 / (double)iterations;

  printf( "  mul:     %12.0f ops/sec  (%6.2f ns/op)\n", ops_per_sec, ns_per_op );
}

/* Benchmark field squaring */
static void
bench_sqr( int iterations ) {
  at_f25519_t a, r;

  for( int i = 0; i < NUM_LIMBS; i++ ) {
    a.el[i] = 0x123456789ABCULL + i;
  }

  /* Warmup */
  for( int i = 0; i < 1000; i++ ) {
    at_f25519_sqr( &r, &a );
    a = r;
  }

  double start = get_time_sec();
  for( int i = 0; i < iterations; i++ ) {
    at_f25519_sqr( &r, &a );
    a = r;
  }
  double end = get_time_sec();

  double elapsed = end - start;
  double ops_per_sec = (double)iterations / elapsed;
  double ns_per_op = elapsed * 1e9 / (double)iterations;

  printf( "  sqr:     %12.0f ops/sec  (%6.2f ns/op)\n", ops_per_sec, ns_per_op );
}

/* Benchmark add/sub */
static void
bench_add( int iterations ) {
  at_f25519_t a, b, r;

  for( int i = 0; i < NUM_LIMBS; i++ ) {
    a.el[i] = 0x123456789ABCULL + i;
    b.el[i] = 0xFEDCBA987654ULL + i;
  }

  /* Warmup */
  for( int i = 0; i < 1000; i++ ) {
    at_f25519_add( &r, &a, &b );
    a = r;
  }

  double start = get_time_sec();
  for( int i = 0; i < iterations; i++ ) {
    at_f25519_add( &r, &a, &b );
    a = r;
  }
  double end = get_time_sec();

  double elapsed = end - start;
  double ops_per_sec = (double)iterations / elapsed;
  double ns_per_op = elapsed * 1e9 / (double)iterations;

  printf( "  add:     %12.0f ops/sec  (%6.2f ns/op)\n", ops_per_sec, ns_per_op );
}

#if AT_HAS_AVX && !AT_HAS_AVX512_IFMA
/* Benchmark SIMD mul4 (AVX2 only) - uses at_f25519_mul4 wrapper */
static void
bench_mul4( int iterations ) {
  at_f25519_t a1, a2, a3, a4;
  at_f25519_t b1, b2, b3, b4;
  at_f25519_t r1, r2, r3, r4;

  for( int i = 0; i < NUM_LIMBS; i++ ) {
    a1.el[i] = 0x123456789ABCULL + i;
    a2.el[i] = 0x234567890ABCULL + i;
    a3.el[i] = 0x345678901ABCULL + i;
    a4.el[i] = 0x456789012ABCULL + i;
    b1.el[i] = 0xFEDCBA987654ULL + i;
    b2.el[i] = 0xEDCBA9876543ULL + i;
    b3.el[i] = 0xDCBA98765432ULL + i;
    b4.el[i] = 0xCBA987654321ULL + i;
  }

  /* Warmup */
  for( int i = 0; i < 1000; i++ ) {
    at_f25519_mul4( &r1, &a1, &b1, &r2, &a2, &b2,
                    &r3, &a3, &b3, &r4, &a4, &b4 );
  }

  double start = get_time_sec();
  for( int i = 0; i < iterations; i++ ) {
    at_f25519_mul4( &r1, &a1, &b1, &r2, &a2, &b2,
                    &r3, &a3, &b3, &r4, &a4, &b4 );
  }
  double end = get_time_sec();

  double elapsed = end - start;
  /* Each iteration processes 4 field elements */
  double ops_per_sec = (double)iterations * 4.0 / elapsed;
  double ns_per_op = elapsed * 1e9 / ((double)iterations * 4.0);

  printf( "  mul4:    %12.0f ops/sec  (%6.2f ns/op)  [4-way SIMD]\n", ops_per_sec, ns_per_op );
}

static void
bench_sqr4( int iterations ) {
  at_f25519_t a1, a2, a3, a4;
  at_f25519_t r1, r2, r3, r4;

  for( int i = 0; i < NUM_LIMBS; i++ ) {
    a1.el[i] = 0x123456789ABCULL + i;
    a2.el[i] = 0x234567890ABCULL + i;
    a3.el[i] = 0x345678901ABCULL + i;
    a4.el[i] = 0x456789012ABCULL + i;
  }

  /* Warmup */
  for( int i = 0; i < 1000; i++ ) {
    at_f25519_sqr4( &r1, &a1, &r2, &a2, &r3, &a3, &r4, &a4 );
  }

  double start = get_time_sec();
  for( int i = 0; i < iterations; i++ ) {
    at_f25519_sqr4( &r1, &a1, &r2, &a2, &r3, &a3, &r4, &a4 );
  }
  double end = get_time_sec();

  double elapsed = end - start;
  double ops_per_sec = (double)iterations * 4.0 / elapsed;
  double ns_per_op = elapsed * 1e9 / ((double)iterations * 4.0);

  printf( "  sqr4:    %12.0f ops/sec  (%6.2f ns/op)  [4-way SIMD]\n", ops_per_sec, ns_per_op );
}
#endif

int main( void ) {
  printf( "=== Field Arithmetic Benchmark: %s ===\n\n", BENCH_NAME );

#if AT_HAS_AVX && !AT_HAS_AVX512_IFMA
  at_ed25519_avx2_init_constants();
#endif

  int iterations = 10000000;  /* 10M iterations */

  printf( "Running %d iterations per benchmark...\n\n", iterations );

  bench_mul( iterations );
  bench_sqr( iterations );
  bench_add( iterations );

#if AT_HAS_AVX && !AT_HAS_AVX512_IFMA
  printf( "\nSIMD operations (4 elements per call):\n" );
  bench_mul4( iterations / 4 );
  bench_sqr4( iterations / 4 );
#endif

  printf( "\nDone.\n" );
  return 0;
}
