/* Test w-NAF scalar multiplication correctness

   Compile:
     cc -O2 -march=native -D_GNU_SOURCE -DAT_HAS_AVX=1 -DAT_HAS_AVX512_IFMA=0 \
        -I../../../include -I../../.. test_wnaf_scalarmul.c \
        ../../../build/native/lib/libat_crypto.a \
        ../../../build/native/lib/libat_util.a -o test_wnaf -lm
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define _GNU_SOURCE
#include <time.h>

#include "avx2/at_curve25519.h"
#include "avx2/at_curve25519.c"

/* Simple PRNG for testing */
static uint64_t rng_state = 0x123456789ABCDEF0ULL;

static uint64_t
xorshift64( void ) {
  uint64_t x = rng_state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  rng_state = x;
  return x;
}

static void
random_scalar( uchar scalar[32] ) {
  for( int i = 0; i < 32; i += 8 ) {
    uint64_t r = xorshift64();
    for( int j = 0; j < 8 && i+j < 32; j++ ) {
      scalar[i+j] = (uchar)(r >> (j*8));
    }
  }
  /* Clamp to valid Ed25519 scalar range */
  scalar[31] &= 0x7F;
}

static double
get_time_sec( void ) {
  struct timespec ts;
  clock_gettime( CLOCK_MONOTONIC, &ts );
  return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* Compare two points by serializing */
static int
points_equal( at_ed25519_point_t const * a,
              at_ed25519_point_t const * b ) {
  uchar buf_a[32], buf_b[32];
  at_ed25519_point_tobytes( buf_a, a );
  at_ed25519_point_tobytes( buf_b, b );
  return memcmp( buf_a, buf_b, 32 ) == 0;
}

static void
print_point_bytes( char const * name, at_ed25519_point_t const * p ) {
  uchar buf[32];
  at_ed25519_point_tobytes( buf, p );
  printf( "  %s: ", name );
  for( int i = 0; i < 32; i++ ) {
    printf( "%02x", buf[i] );
  }
  printf( "\n" );
}

static void
print_point_limbs( char const * name, at_ed25519_point_t const * p ) {
  printf( "  %s X[0-2]: %016lx %016lx %016lx\n", name,
          p->X->el[0], p->X->el[1], p->X->el[2] );
  printf( "  %s Y[0-2]: %016lx %016lx %016lx\n", name,
          p->Y->el[0], p->Y->el[1], p->Y->el[2] );
  printf( "  %s Z[0-2]: %016lx %016lx %016lx\n", name,
          p->Z->el[0], p->Z->el[1], p->Z->el[2] );
}

int main( void ) {
  printf( "=== w-NAF Scalar Multiplication Tests ===\n\n" );

  /* Initialize constants */
  at_ed25519_avx2_init_constants();

  int failures = 0;

  /* Test 1: n*B using w-NAF vs simple double-and-add */
  printf( "Test 1: w-NAF vs double-and-add (1000 random scalars)...\n" );
  {
    int pass = 1;
    for( int i = 0; i < 1000; i++ ) {
      uchar scalar[32];
      random_scalar( scalar );

      at_ed25519_point_t r_wnaf[1], r_simple[1];

      /* w-NAF method */
      at_ed25519_scalar_mul_base_wnaf( r_wnaf, scalar );

      /* Simple double-and-add */
      at_ed25519_point_scalarmul_vartime( r_simple, scalar, at_ed25519_base_point );

      if( !points_equal( r_wnaf, r_simple ) ) {
        printf( "  FAIL at iteration %d\n", i );
        printf( "  scalar: " );
        for( int j = 0; j < 32; j++ ) printf( "%02x", scalar[j] );
        printf( "\n" );
        print_point_bytes( "w-NAF  ", r_wnaf );
        print_point_bytes( "simple ", r_simple );
        pass = 0;
        break;
      }
    }
    if( pass ) {
      printf( "  PASS\n" );
    } else {
      failures++;
    }
  }

  /* Test 2: Known scalar */
  printf( "Test 2: Known scalar (1)...\n" );
  {
    uchar scalar_one[32] = { 1 };
    at_ed25519_point_t r[1];

    at_ed25519_scalar_mul_base_wnaf( r, scalar_one );

    /* 1*B should equal B */
    if( points_equal( r, at_ed25519_base_point ) ) {
      printf( "  PASS: 1*B == B\n" );
    } else {
      printf( "  FAIL: 1*B != B\n" );
      failures++;
    }
  }

  /* Test 3: Known scalar (2) */
  printf( "Test 3: Known scalar (2)...\n" );
  {
    uchar scalar_two[32] = { 2 };
    at_ed25519_point_t r[1], expected[1];

    at_ed25519_scalar_mul_base_wnaf( r, scalar_two );
    at_ed25519_point_dbl( expected, at_ed25519_base_point );

    /* 2*B should equal B+B */
    if( points_equal( r, expected ) ) {
      printf( "  PASS: 2*B == B+B\n" );
    } else {
      printf( "  FAIL: 2*B != B+B\n" );
      print_point_bytes( "w-NAF 2*B", r );
      print_point_bytes( "dbl(B)   ", expected );

      /* Debug: compute 2*B via adding B+B */
      at_ed25519_point_t bb[1];
      at_ed25519_point_add( bb, at_ed25519_base_point, at_ed25519_base_point );
      print_point_bytes( "B+B (add)", bb );

      /* Debug: What does table[0] look like after adding to identity? */
      at_ed25519_point_t from_table[1];
      at_ed25519_point_set_zero( from_table );
      at_ed25519_point_add_precomputed( from_table, from_table,
                                        &at_ed25519_base_point_wnaf_table[0], 0 );
      print_point_bytes( "table[0]+id", from_table );
      print_point_bytes( "base point ", at_ed25519_base_point );

      /* Debug: double the table[0] result */
      at_ed25519_point_t dbl_table[1];
      at_ed25519_point_dbl( dbl_table, from_table );
      print_point_bytes( "dbl(tbl[0])", dbl_table );

      /* Debug: print limb values to compare internal representations */
      printf( "\n  Internal limb values (first 3 of each):\n" );
      print_point_limbs( "from_table", from_table );
      print_point_limbs( "base_point", at_ed25519_base_point );

      failures++;
    }
  }

  /* Test 4: Scalar 0 should give identity */
  printf( "Test 4: Scalar 0 gives identity...\n" );
  {
    uchar scalar_zero[32] = { 0 };
    at_ed25519_point_t r[1];

    at_ed25519_scalar_mul_base_wnaf( r, scalar_zero );

    if( at_ed25519_point_is_zero( r ) ) {
      printf( "  PASS: 0*B == identity\n" );
    } else {
      printf( "  FAIL: 0*B != identity\n" );
      print_point_bytes( "w-NAF 0*B", r );

      /* Also print identity for comparison */
      at_ed25519_point_t id[1];
      at_ed25519_point_set_zero( id );
      print_point_bytes( "identity ", id );
      failures++;
    }
  }

  /* Test 5: Double scalar multiplication */
  printf( "Test 5: Double scalar mul (n1*P + n2*B) (100 iterations)...\n" );
  {
    int pass = 1;
    for( int i = 0; i < 100; i++ ) {
      uchar n1[32], n2[32];
      random_scalar( n1 );
      random_scalar( n2 );

      /* Create a random point P = k*B */
      uchar k[32];
      random_scalar( k );
      at_ed25519_point_t P[1];
      at_ed25519_scalar_mul_base( P, k );

      /* Compute using double_scalar_mul_base */
      at_ed25519_point_t r1[1];
      at_ed25519_double_scalar_mul_base( r1, n1, P, n2 );

      /* Compute manually: n1*P + n2*B */
      at_ed25519_point_t t1[1], t2[1], r2[1];
      at_ed25519_point_scalarmul_vartime( t1, n1, P );
      at_ed25519_scalar_mul_base( t2, n2 );
      at_ed25519_point_add( r2, t1, t2 );

      if( !points_equal( r1, r2 ) ) {
        printf( "  FAIL at iteration %d\n", i );
        pass = 0;
        break;
      }
    }
    if( pass ) {
      printf( "  PASS\n" );
    } else {
      failures++;
    }
  }

  /* Performance benchmark */
  printf( "\n=== Performance Benchmark ===\n\n" );

  {
    int iterations = 10000;
    uchar scalar[32];
    random_scalar( scalar );
    at_ed25519_point_t r[1];

    /* Warmup */
    for( int i = 0; i < 100; i++ ) {
      at_ed25519_scalar_mul_base_wnaf( r, scalar );
    }

    /* Benchmark w-NAF */
    double start = get_time_sec();
    for( int i = 0; i < iterations; i++ ) {
      at_ed25519_scalar_mul_base_wnaf( r, scalar );
    }
    double wnaf_time = get_time_sec() - start;

    /* Benchmark simple */
    start = get_time_sec();
    for( int i = 0; i < iterations; i++ ) {
      at_ed25519_point_scalarmul_vartime( r, scalar, at_ed25519_base_point );
    }
    double simple_time = get_time_sec() - start;

    printf( "w-NAF scalar mul:   %.0f ops/sec (%.2f us/op)\n",
            iterations / wnaf_time, wnaf_time / iterations * 1e6 );
    printf( "Simple scalar mul:  %.0f ops/sec (%.2f us/op)\n",
            iterations / simple_time, simple_time / iterations * 1e6 );
    printf( "Speedup: %.2fx\n", simple_time / wnaf_time );
  }

  printf( "\n=== Summary ===\n" );
  printf( "Total failures: %d\n", failures );

  if( failures == 0 ) {
    printf( "\n*** ALL TESTS PASSED ***\n" );
  }

  return failures;
}
