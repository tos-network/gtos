/* AVX-512F General Higher-Level Operations Comparison Tests

   This test compares higher-level field operations (pow22523, sqrt_ratio, etc.)
   between the AVX-512F General implementation and the fiat-crypto reference.
   The goal is to find discrepancies that cause VRF failures on AVX-512 systems.

   Compile (standalone):
   cc -std=c17 -O2 -march=skylake-avx512 -D_GNU_SOURCE -DAT_HAS_AVX512=1 \
      -DAT_HAS_AVX512_GENERAL=1 -Iinclude -Isrc -Isrc/crypto/ed25519 \
      test_avx512_general_higher_ops.c -o test_avx512_general_higher_ops -lm
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ========================================================================
   Reference Implementation (fiat-crypto, 5-limb radix-2^51)
   ======================================================================== */

/* Include fiat-crypto directly for reference implementation */
#include "at/crypto/fiat-crypto/curve25519_64.c"

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

static inline int
ref_is_zero( ref_fe_t const * a ) {
  unsigned char bytes[32];
  ref_tobytes( bytes, a );
  int zero = 1;
  for( int i = 0; i < 32; i++ ) {
    if( bytes[i] != 0 ) zero = 0;
  }
  return zero;
}

static inline int
ref_eq( ref_fe_t const * a, ref_fe_t const * b ) {
  ref_fe_t diff;
  ref_sub( &diff, a, b );
  return ref_is_zero( &diff );
}

/* Reference sgn - returns LSB of serialized form */
static inline int
ref_sgn( ref_fe_t const * a ) {
  unsigned char bytes[32];
  ref_tobytes( bytes, a );
  return bytes[0] & 1;
}

/* Reference abs - conditional negate based on sign */
static inline void
ref_abs( ref_fe_t * r, ref_fe_t const * a ) {
  if( ref_sgn( a ) ) {
    ref_neg( r, a );
  } else {
    *r = *a;
  }
}

/* Reference pow22523 - computes a^((p-5)/8) = a^(2^252-3) */
static void
ref_pow22523( ref_fe_t * r, ref_fe_t const * a ) {
  ref_fe_t t0, t1, t2;

  ref_sqr( &t0, a );
  ref_sqr( &t1, &t0 );
  for( int i = 1; i < 2; i++ ) ref_sqr( &t1, &t1 );

  ref_mul( &t1, a, &t1 );
  ref_mul( &t0, &t0, &t1 );
  ref_sqr( &t0, &t0 );
  ref_mul( &t0, &t1, &t0 );
  ref_sqr( &t1, &t0 );
  for( int i = 1; i < 5; i++ ) ref_sqr( &t1, &t1 );

  ref_mul( &t0, &t1, &t0 );
  ref_sqr( &t1, &t0 );
  for( int i = 1; i < 10; i++ ) ref_sqr( &t1, &t1 );

  ref_mul( &t1, &t1, &t0 );
  ref_sqr( &t2, &t1 );
  for( int i = 1; i < 20; i++ ) ref_sqr( &t2, &t2 );

  ref_mul( &t1, &t2, &t1 );
  ref_sqr( &t1, &t1 );
  for( int i = 1; i < 10; i++ ) ref_sqr( &t1, &t1 );

  ref_mul( &t0, &t1, &t0 );
  ref_sqr( &t1, &t0 );
  for( int i = 1; i < 50; i++ ) ref_sqr( &t1, &t1 );

  ref_mul( &t1, &t1, &t0 );
  ref_sqr( &t2, &t1 );
  for( int i = 1; i < 100; i++ ) ref_sqr( &t2, &t2 );

  ref_mul( &t1, &t2, &t1 );
  ref_sqr( &t1, &t1 );
  for( int i = 1; i < 50; i++ ) ref_sqr( &t1, &t1 );

  ref_mul( &t0, &t1, &t0 );
  ref_sqr( &t0, &t0 );
  for( int i = 1; i < 2; i++ ) ref_sqr( &t0, &t0 );

  ref_mul( r, &t0, a );
}

/* sqrt(-1) mod p */
static const unsigned char ref_sqrtm1_bytes[32] = {
  0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
  0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
  0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
  0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b
};

/* Reference sqrt_ratio - computes sqrt(u/v) using SQRT_RATIO_M1 algorithm */
static int
ref_sqrt_ratio( ref_fe_t * r, ref_fe_t const * u, ref_fe_t const * v ) {
  ref_fe_t sqrtm1;
  ref_frombytes( &sqrtm1, ref_sqrtm1_bytes );

  ref_fe_t v2; ref_sqr( &v2, v );
  ref_fe_t v3; ref_mul( &v3, &v2, v );
  ref_fe_t uv3; ref_mul( &uv3, u, &v3 );
  ref_fe_t v6; ref_sqr( &v6, &v3 );
  ref_fe_t v7; ref_mul( &v7, &v6, v );
  ref_fe_t uv7; ref_mul( &uv7, u, &v7 );
  ref_pow22523( r, &uv7 );
  ref_mul( r, r, &uv3 );

  ref_fe_t check;
  ref_sqr( &check, r );
  ref_mul( &check, &check, v );

  ref_fe_t u_neg; ref_neg( &u_neg, u );
  ref_fe_t u_neg_sqrtm1; ref_mul( &u_neg_sqrtm1, &u_neg, &sqrtm1 );

  int correct_sign_sqrt = ref_eq( &check, u );
  int flipped_sign_sqrt = ref_eq( &check, &u_neg );
  int flipped_sign_sqrt_i = ref_eq( &check, &u_neg_sqrtm1 );

  ref_fe_t r_prime;
  ref_mul( &r_prime, r, &sqrtm1 );

  if( flipped_sign_sqrt | flipped_sign_sqrt_i ) {
    *r = r_prime;
  }
  ref_abs( r, r );
  return correct_sign_sqrt | flipped_sign_sqrt;
}

/* ========================================================================
   AVX-512F General Implementation (12-limb radix-2^25.5)
   ======================================================================== */

#if AT_HAS_AVX512_GENERAL

/* Include the local AVX-512 General implementation directly */
#include "at_f25519.h"

typedef at_f25519_t avx512_fe_t;

#define avx512_frombytes at_f25519_frombytes
#define avx512_tobytes at_f25519_tobytes
#define avx512_mul at_f25519_mul
#define avx512_sqr at_f25519_sqr
#define avx512_add at_f25519_add
#define avx512_sub at_f25519_sub
#define avx512_neg at_f25519_neg
#define avx512_pow22523 at_f25519_pow22523
#define avx512_sqrt_ratio at_f25519_sqrt_ratio
#define avx512_sgn at_f25519_sgn
#define avx512_abs at_f25519_abs
#define avx512_is_zero at_f25519_is_zero

/* ========================================================================
   Test Utilities
   ======================================================================== */

static void
print_hex( char const * name, unsigned char const * data, int len ) {
  printf( "%s: ", name );
  for( int i = 0; i < len; i++ ) printf( "%02x", data[i] );
  printf( "\n" );
}

static void
random_bytes( unsigned char * out, int len ) {
  for( int i = 0; i < len; i++ ) {
    out[i] = (unsigned char)rand();
  }
  /* Clear top bit to ensure valid field element */
  out[31] &= 0x7f;
}

/* ========================================================================
   Tests
   ======================================================================== */

/* Test pow22523 */
static int
test_pow22523( int iterations ) {
  printf( "Testing pow22523 (%d iterations)...\n", iterations );
  int failures = 0;

  for( int i = 0; i < iterations; i++ ) {
    unsigned char input[32];
    random_bytes( input, 32 );

    /* Reference */
    ref_fe_t ref_in, ref_out;
    ref_frombytes( &ref_in, input );
    ref_pow22523( &ref_out, &ref_in );
    unsigned char ref_result[32];
    ref_tobytes( ref_result, &ref_out );

    /* AVX-512 General */
    avx512_fe_t avx_in, avx_out;
    avx512_frombytes( &avx_in, input );
    avx512_pow22523( &avx_out, &avx_in );
    unsigned char avx_result[32];
    avx512_tobytes( avx_result, &avx_out );

    if( memcmp( ref_result, avx_result, 32 ) != 0 ) {
      printf( "  MISMATCH at iteration %d:\n", i );
      print_hex( "    input", input, 32 );
      print_hex( "    ref  ", ref_result, 32 );
      print_hex( "    avx  ", avx_result, 32 );
      failures++;
      if( failures >= 5 ) {
        printf( "  ... stopping after 5 failures\n" );
        break;
      }
    }
  }

  if( failures == 0 ) {
    printf( "  PASS\n" );
  } else {
    printf( "  FAIL (%d mismatches)\n", failures );
  }
  return failures;
}

/* Test sqrt_ratio */
static int
test_sqrt_ratio( int iterations ) {
  printf( "Testing sqrt_ratio (%d iterations)...\n", iterations );
  int failures = 0;

  for( int i = 0; i < iterations; i++ ) {
    unsigned char u_bytes[32], v_bytes[32];
    random_bytes( u_bytes, 32 );
    random_bytes( v_bytes, 32 );

    /* Reference */
    ref_fe_t ref_u, ref_v, ref_r;
    ref_frombytes( &ref_u, u_bytes );
    ref_frombytes( &ref_v, v_bytes );
    int ref_ret = ref_sqrt_ratio( &ref_r, &ref_u, &ref_v );
    unsigned char ref_result[32];
    ref_tobytes( ref_result, &ref_r );

    /* AVX-512 General */
    avx512_fe_t avx_u, avx_v, avx_r;
    avx512_frombytes( &avx_u, u_bytes );
    avx512_frombytes( &avx_v, v_bytes );
    int avx_ret = avx512_sqrt_ratio( &avx_r, &avx_u, &avx_v );
    unsigned char avx_result[32];
    avx512_tobytes( avx_result, &avx_r );

    if( ref_ret != avx_ret || memcmp( ref_result, avx_result, 32 ) != 0 ) {
      printf( "  MISMATCH at iteration %d:\n", i );
      print_hex( "    u    ", u_bytes, 32 );
      print_hex( "    v    ", v_bytes, 32 );
      printf( "    ref_ret=%d, avx_ret=%d\n", ref_ret, avx_ret );
      print_hex( "    ref_r", ref_result, 32 );
      print_hex( "    avx_r", avx_result, 32 );
      failures++;
      if( failures >= 5 ) {
        printf( "  ... stopping after 5 failures\n" );
        break;
      }
    }
  }

  if( failures == 0 ) {
    printf( "  PASS\n" );
  } else {
    printf( "  FAIL (%d mismatches)\n", failures );
  }
  return failures;
}

/* Test sgn */
static int
test_sgn( int iterations ) {
  printf( "Testing sgn (%d iterations)...\n", iterations );
  int failures = 0;

  for( int i = 0; i < iterations; i++ ) {
    unsigned char input[32];
    random_bytes( input, 32 );

    /* Reference */
    ref_fe_t ref_a;
    ref_frombytes( &ref_a, input );
    int ref_result = ref_sgn( &ref_a );

    /* AVX-512 General */
    avx512_fe_t avx_a;
    avx512_frombytes( &avx_a, input );
    int avx_result = avx512_sgn( &avx_a );

    if( ref_result != avx_result ) {
      printf( "  MISMATCH at iteration %d:\n", i );
      print_hex( "    input", input, 32 );
      printf( "    ref_sgn=%d, avx_sgn=%d\n", ref_result, avx_result );
      failures++;
      if( failures >= 5 ) break;
    }
  }

  if( failures == 0 ) {
    printf( "  PASS\n" );
  } else {
    printf( "  FAIL (%d mismatches)\n", failures );
  }
  return failures;
}

/* Test abs */
static int
test_abs( int iterations ) {
  printf( "Testing abs (%d iterations)...\n", iterations );
  int failures = 0;

  for( int i = 0; i < iterations; i++ ) {
    unsigned char input[32];
    random_bytes( input, 32 );

    /* Reference */
    ref_fe_t ref_a, ref_out;
    ref_frombytes( &ref_a, input );
    ref_abs( &ref_out, &ref_a );
    unsigned char ref_result[32];
    ref_tobytes( ref_result, &ref_out );

    /* AVX-512 General */
    avx512_fe_t avx_a, avx_out;
    avx512_frombytes( &avx_a, input );
    avx512_abs( &avx_out, &avx_a );
    unsigned char avx_result[32];
    avx512_tobytes( avx_result, &avx_out );

    if( memcmp( ref_result, avx_result, 32 ) != 0 ) {
      printf( "  MISMATCH at iteration %d:\n", i );
      print_hex( "    input", input, 32 );
      print_hex( "    ref  ", ref_result, 32 );
      print_hex( "    avx  ", avx_result, 32 );
      failures++;
      if( failures >= 5 ) break;
    }
  }

  if( failures == 0 ) {
    printf( "  PASS\n" );
  } else {
    printf( "  FAIL (%d mismatches)\n", failures );
  }
  return failures;
}

/* Test is_zero */
static int
test_is_zero( void ) {
  printf( "Testing is_zero...\n" );
  int failures = 0;

  /* Test actual zero */
  unsigned char zero_bytes[32] = {0};
  ref_fe_t ref_zero;
  ref_frombytes( &ref_zero, zero_bytes );
  int ref_z = ref_is_zero( &ref_zero );

  avx512_fe_t avx_zero;
  avx512_frombytes( &avx_zero, zero_bytes );
  int avx_z = avx512_is_zero( &avx_zero );

  if( ref_z != avx_z || ref_z != 1 ) {
    printf( "  MISMATCH: zero test, ref=%d, avx=%d (expected 1)\n", ref_z, avx_z );
    failures++;
  }

  /* Test non-zero */
  unsigned char one_bytes[32] = {1};
  ref_fe_t ref_one;
  ref_frombytes( &ref_one, one_bytes );
  int ref_nz = ref_is_zero( &ref_one );

  avx512_fe_t avx_one;
  avx512_frombytes( &avx_one, one_bytes );
  int avx_nz = avx512_is_zero( &avx_one );

  if( ref_nz != avx_nz || ref_nz != 0 ) {
    printf( "  MISMATCH: non-zero test, ref=%d, avx=%d (expected 0)\n", ref_nz, avx_nz );
    failures++;
  }

  if( failures == 0 ) {
    printf( "  PASS\n" );
  } else {
    printf( "  FAIL\n" );
  }
  return failures;
}

/* Test with specific problematic values that might trigger bugs */
static int
test_edge_cases( void ) {
  printf( "Testing edge cases...\n" );
  int failures = 0;

  /* Test case 1: u = 1, v = 1 (trivial sqrt) */
  {
    unsigned char u_bytes[32] = {1};
    unsigned char v_bytes[32] = {1};

    ref_fe_t ref_u, ref_v, ref_r;
    ref_frombytes( &ref_u, u_bytes );
    ref_frombytes( &ref_v, v_bytes );
    int ref_ret = ref_sqrt_ratio( &ref_r, &ref_u, &ref_v );
    unsigned char ref_result[32];
    ref_tobytes( ref_result, &ref_r );

    avx512_fe_t avx_u, avx_v, avx_r;
    avx512_frombytes( &avx_u, u_bytes );
    avx512_frombytes( &avx_v, v_bytes );
    int avx_ret = avx512_sqrt_ratio( &avx_r, &avx_u, &avx_v );
    unsigned char avx_result[32];
    avx512_tobytes( avx_result, &avx_r );

    if( ref_ret != avx_ret || memcmp( ref_result, avx_result, 32 ) != 0 ) {
      printf( "  MISMATCH (u=1, v=1):\n" );
      printf( "    ref_ret=%d, avx_ret=%d\n", ref_ret, avx_ret );
      print_hex( "    ref_r", ref_result, 32 );
      print_hex( "    avx_r", avx_result, 32 );
      failures++;
    }
  }

  /* Test case 2: u = 0, v = 1 (should yield 0) */
  {
    unsigned char u_bytes[32] = {0};
    unsigned char v_bytes[32] = {1};

    ref_fe_t ref_u, ref_v, ref_r;
    ref_frombytes( &ref_u, u_bytes );
    ref_frombytes( &ref_v, v_bytes );
    int ref_ret = ref_sqrt_ratio( &ref_r, &ref_u, &ref_v );
    unsigned char ref_result[32];
    ref_tobytes( ref_result, &ref_r );

    avx512_fe_t avx_u, avx_v, avx_r;
    avx512_frombytes( &avx_u, u_bytes );
    avx512_frombytes( &avx_v, v_bytes );
    int avx_ret = avx512_sqrt_ratio( &avx_r, &avx_u, &avx_v );
    unsigned char avx_result[32];
    avx512_tobytes( avx_result, &avx_r );

    if( ref_ret != avx_ret || memcmp( ref_result, avx_result, 32 ) != 0 ) {
      printf( "  MISMATCH (u=0, v=1):\n" );
      printf( "    ref_ret=%d, avx_ret=%d\n", ref_ret, avx_ret );
      print_hex( "    ref_r", ref_result, 32 );
      print_hex( "    avx_r", avx_result, 32 );
      failures++;
    }
  }

  /* Test case 3: Known test vector from ristretto255 spec */
  {
    /* This is a case where the square root exists */
    unsigned char u_bytes[32] = {
      0x67, 0x68, 0x06, 0x02, 0xa3, 0xf1, 0x9a, 0x3e,
      0x0d, 0x0a, 0xbb, 0xce, 0x52, 0x8a, 0x6b, 0x49,
      0x1c, 0x01, 0x62, 0xb4, 0x7a, 0x29, 0xe3, 0x77,
      0x63, 0x3c, 0x0e, 0x7f, 0x9b, 0xa1, 0x53, 0x0b
    };
    unsigned char v_bytes[32] = {1};

    ref_fe_t ref_u, ref_v, ref_r;
    ref_frombytes( &ref_u, u_bytes );
    ref_frombytes( &ref_v, v_bytes );
    int ref_ret = ref_sqrt_ratio( &ref_r, &ref_u, &ref_v );
    unsigned char ref_result[32];
    ref_tobytes( ref_result, &ref_r );

    avx512_fe_t avx_u, avx_v, avx_r;
    avx512_frombytes( &avx_u, u_bytes );
    avx512_frombytes( &avx_v, v_bytes );
    int avx_ret = avx512_sqrt_ratio( &avx_r, &avx_u, &avx_v );
    unsigned char avx_result[32];
    avx512_tobytes( avx_result, &avx_r );

    printf( "  Edge case 3 (known vector): ref_ret=%d, avx_ret=%d\n", ref_ret, avx_ret );
    print_hex( "    ref_r", ref_result, 32 );
    print_hex( "    avx_r", avx_result, 32 );

    if( ref_ret != avx_ret || memcmp( ref_result, avx_result, 32 ) != 0 ) {
      printf( "  MISMATCH\n" );
      failures++;
    }
  }

  if( failures == 0 ) {
    printf( "  PASS\n" );
  } else {
    printf( "  FAIL\n" );
  }
  return failures;
}

/* External declaration for init function */
extern void at_ed25519_avx512_general_init_constants( void );

int
main( int argc, char ** argv ) {
  (void)argc; (void)argv;

  printf( "=== AVX-512 General vs Reference: Higher-Level Operations ===\n\n" );

  /* Initialize AVX-512 General constants (sqrtm1, etc.) */
  printf( "Initializing AVX-512 General constants...\n" );
  at_ed25519_avx512_general_init_constants();

  srand( 12345 ); /* Fixed seed for reproducibility */

  int total_failures = 0;

  /* Test individual operations in order of complexity */
  total_failures += test_is_zero();
  total_failures += test_sgn( 1000 );
  total_failures += test_abs( 1000 );
  total_failures += test_pow22523( 1000 );
  total_failures += test_sqrt_ratio( 1000 );
  total_failures += test_edge_cases();

  printf( "\n=== Summary ===\n" );
  if( total_failures == 0 ) {
    printf( "ALL TESTS PASSED\n" );
    return 0;
  } else {
    printf( "TOTAL FAILURES: %d\n", total_failures );
    return 1;
  }
}

#else /* !AT_HAS_AVX512_GENERAL */

int
main( int argc, char ** argv ) {
  (void)argc; (void)argv;
  printf( "AVX-512 General not available on this platform, skipping tests.\n" );
  return 0;
}

#endif /* AT_HAS_AVX512_GENERAL */
