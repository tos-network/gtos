/* AVX2 Precomputed Table Generator

   This tool generates precomputed tables for AVX2 Ed25519 operations.
   The tables use radix-2^25.5 representation (10 limbs with alternating 26/25 bits).

   Compile:
     cc -std=c17 -O2 gen_avx2_tables.c -o /tmp/gen_avx2_tables

   Run:
     /tmp/gen_avx2_tables > table/at_curve25519_table_avx2.c
*/

#include <stdio.h>
#include <stdint.h>
#include "../../infra/at_util_base.h"

/* Use fiat-crypto for reference computations */
#include "../fiat-crypto/curve25519_64.c"

/* Field element in radix-2^51 (5 limbs) - fiat-crypto format */
typedef uint64_t fe51[5];

/* Field element in radix-2^25.5 (10 limbs) - AVX2 format */
typedef uint64_t fe2526[10];

/* Ed25519 point in extended coordinates */
typedef struct {
  fe51 X;
  fe51 Y;
  fe51 T;
  fe51 Z;
} ge_p3;

/* Constants */
#define MASK26 ((uint64_t)0x3FFFFFF)
#define MASK25 ((uint64_t)0x1FFFFFF)

/* d = -121665/121666 mod p */
static const uint8_t d_bytes[32] = {
  0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
  0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
  0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
  0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52
};

/* k = 2d mod p */
static const uint8_t k_bytes[32] = {
  0x47, 0xf1, 0xb2, 0x26, 0x94, 0x9b, 0xd6, 0xeb,
  0x56, 0xb1, 0x83, 0x82, 0x9a, 0x14, 0xe0, 0x00,
  0x30, 0xd1, 0xf3, 0xee, 0xf2, 0x80, 0x8e, 0x19,
  0xe7, 0xfc, 0xdf, 0x56, 0xdc, 0xd9, 0x06, 0x24
};

/* sqrt(-1) mod p */
static const uint8_t sqrtm1_bytes[32] = {
  0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
  0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
  0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
  0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b
};

/* Base point Y coordinate */
static const uint8_t base_y_bytes[32] = {
  0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

/* Low-order points */
static const uint8_t order8_y0_bytes[32] = {
  0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
  0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
  0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
  0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05
};

static const uint8_t order8_y1_bytes[32] = {
  0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
  0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
  0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
  0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a
};

/* Field element constants */
static fe51 fe_d;
static fe51 fe_sqrtm1;
static fe51 fe_k;
static fe51 fe_one = { 1, 0, 0, 0, 0 };
static fe51 fe_zero = { 0, 0, 0, 0, 0 };

/* ========================================================================
   Field Operations (radix-2^51)
   ======================================================================== */

static void
fe_frombytes( fe51 h, const uint8_t s[32] ) {
  fiat_25519_from_bytes( h, s );
}

static void
fe_tobytes( uint8_t s[32], const fe51 h ) {
  fiat_25519_to_bytes( s, h );
}

static void
fe_add( fe51 h, const fe51 f, const fe51 g ) {
  uint64_t t[5];
  fiat_25519_add( t, f, g );
  fiat_25519_carry( h, t );
}

static void
fe_sub( fe51 h, const fe51 f, const fe51 g ) {
  uint64_t t[5];
  fiat_25519_sub( t, f, g );
  fiat_25519_carry( h, t );
}

static void
fe_mul( fe51 h, const fe51 f, const fe51 g ) {
  fiat_25519_carry_mul( h, f, g );
}

static void
fe_sq( fe51 h, const fe51 f ) {
  fiat_25519_carry_square( h, f );
}

static void
fe_copy( fe51 h, const fe51 f ) {
  for( int i = 0; i < 5; i++ ) h[i] = f[i];
}

static void
fe_neg( fe51 h, const fe51 f ) {
  fe51 zero = { 0, 0, 0, 0, 0 };
  fe_sub( h, zero, f );
}

/* Check if f == 0 */
static int
fe_iszero( const fe51 f ) {
  uint8_t s[32];
  fe_tobytes( s, f );
  uint8_t d = 0;
  for( int i = 0; i < 32; i++ ) d |= s[i];
  return d == 0;
}

/* Return LSB of f */
static int
fe_isnegative( const fe51 f ) {
  uint8_t s[32];
  fe_tobytes( s, f );
  return s[0] & 1;
}

/* Compute f^(2^252-3) for square root */
static void
fe_pow22523( fe51 out, const fe51 z ) {
  fe51 t0, t1, t2;

  fe_sq( t0, z );
  fe_sq( t1, t0 );
  fe_sq( t1, t1 );
  fe_mul( t1, z, t1 );
  fe_mul( t0, t0, t1 );
  fe_sq( t0, t0 );
  fe_mul( t0, t1, t0 );
  fe_sq( t1, t0 );
  for( int i = 1; i < 5; i++ ) fe_sq( t1, t1 );
  fe_mul( t0, t1, t0 );
  fe_sq( t1, t0 );
  for( int i = 1; i < 10; i++ ) fe_sq( t1, t1 );
  fe_mul( t1, t1, t0 );
  fe_sq( t2, t1 );
  for( int i = 1; i < 20; i++ ) fe_sq( t2, t2 );
  fe_mul( t1, t2, t1 );
  fe_sq( t1, t1 );
  for( int i = 1; i < 10; i++ ) fe_sq( t1, t1 );
  fe_mul( t0, t1, t0 );
  fe_sq( t1, t0 );
  for( int i = 1; i < 50; i++ ) fe_sq( t1, t1 );
  fe_mul( t1, t1, t0 );
  fe_sq( t2, t1 );
  for( int i = 1; i < 100; i++ ) fe_sq( t2, t2 );
  fe_mul( t1, t2, t1 );
  fe_sq( t1, t1 );
  for( int i = 1; i < 50; i++ ) fe_sq( t1, t1 );
  fe_mul( t0, t1, t0 );
  fe_sq( t0, t0 );
  fe_sq( t0, t0 );
  fe_mul( out, t0, z );
}

/* Compute sqrt(u/v) if it exists */
static int
fe_sqrt_ratio( fe51 x, const fe51 u, const fe51 v ) {
  fe51 v3, v7, uv3, uv7, t;

  fe_sq( v3, v );
  fe_mul( v3, v3, v );
  fe_sq( v7, v3 );
  fe_mul( v7, v7, v );

  fe_mul( uv3, u, v3 );
  fe_mul( uv7, u, v7 );

  fe_pow22523( t, uv7 );
  fe_mul( x, uv3, t );

  fe_sq( t, x );
  fe_mul( t, t, v );
  fe_sub( t, t, u );

  if( fe_iszero( t ) ) return 1;

  fe_mul( x, x, fe_sqrtm1 );
  fe_sq( t, x );
  fe_mul( t, t, v );
  fe_sub( t, t, u );

  return fe_iszero( t );
}

/* ========================================================================
   Point Operations
   ======================================================================== */

static void
ge_p3_0( ge_p3 * h ) {
  fe_copy( h->X, fe_zero );
  fe_copy( h->Y, fe_one );
  fe_copy( h->T, fe_zero );
  fe_copy( h->Z, fe_one );
}

static void
ge_p3_dbl( ge_p3 * r, const ge_p3 * p ) {
  fe51 A, B, C, D, E, F, G, H;

  fe_sq( A, p->X );
  fe_sq( B, p->Y );
  fe_sq( C, p->Z );
  fe_add( C, C, C );
  fe_neg( D, A );

  fe_add( E, p->X, p->Y );
  fe_sq( E, E );
  fe_sub( E, E, A );
  fe_sub( E, E, B );

  fe_add( G, D, B );
  fe_sub( F, G, C );
  fe_sub( H, D, B );

  fe_mul( r->X, E, F );
  fe_mul( r->Y, G, H );
  fe_mul( r->T, E, H );
  fe_mul( r->Z, F, G );
}

static void
ge_p3_add( ge_p3 * r, const ge_p3 * p, const ge_p3 * q ) {
  fe51 A, B, C, D, E, F, G, H;
  fe51 t0, t1;

  fe_sub( t0, p->Y, p->X );
  fe_sub( t1, q->Y, q->X );
  fe_mul( A, t0, t1 );
  fe_add( t0, p->Y, p->X );
  fe_add( t1, q->Y, q->X );
  fe_mul( B, t0, t1 );
  fe_mul( t0, p->T, q->T );
  fe_mul( C, t0, fe_k );
  fe_mul( t0, p->Z, q->Z );
  fe_add( D, t0, t0 );

  fe_sub( E, B, A );
  fe_sub( F, D, C );
  fe_add( G, D, C );
  fe_add( H, B, A );

  fe_mul( r->X, E, F );
  fe_mul( r->Y, G, H );
  fe_mul( r->T, E, H );
  fe_mul( r->Z, F, G );
}

static void
ge_scalarmult( ge_p3 * r, const uint8_t * scalar, const ge_p3 * base ) {
  ge_p3 acc;
  ge_p3_0( &acc );

  for( int i = 255; i >= 0; i-- ) {
    ge_p3_dbl( &acc, &acc );
    int bit = (scalar[i/8] >> (i%8)) & 1;
    if( bit ) {
      ge_p3_add( &acc, &acc, base );
    }
  }

  at_memcpy( r, &acc, sizeof(ge_p3) );
}

/* Decompress point from Y coordinate */
static int
ge_frombytes( ge_p3 * h, const uint8_t s[32] ) {
  fe51 u, v, x;

  fe_frombytes( h->Y, s );
  int x_sign = s[31] >> 7;

  fe_sq( u, h->Y );
  fe_mul( v, u, fe_d );
  fe_sub( u, u, fe_one );
  fe_add( v, v, fe_one );

  if( !fe_sqrt_ratio( x, u, v ) ) {
    return -1;
  }

  if( fe_isnegative( x ) != x_sign ) {
    fe_neg( x, x );
  }

  fe_copy( h->X, x );
  fe_copy( h->Z, fe_one );
  fe_mul( h->T, h->X, h->Y );

  return 0;
}

/* Compute modular inverse using Fermat's little theorem: z^(-1) = z^(p-2) */
static void
fe_inv( fe51 out, const fe51 z ) {
  fe51 t;
  fe_pow22523( t, z );
  fe_sq( t, t );
  fe_sq( t, t );
  fe_sq( t, t );
  fe_mul( t, t, z );
  fe_mul( t, t, z );
  fe_mul( out, t, z );
}

/* Compress point to bytes */
static void
ge_tobytes( uint8_t s[32], const ge_p3 * h ) {
  fe51 x, y, zi;

  fe_inv( zi, h->Z );
  fe_mul( x, h->X, zi );
  fe_mul( y, h->Y, zi );

  fe_tobytes( s, y );
  s[31] ^= fe_isnegative( x ) << 7;
}

/* Convert point to affine form (Z=1) */
static void
ge_into_affine( ge_p3 * p ) {
  fe51 zi;
  fe_inv( zi, p->Z );
  fe_mul( p->X, p->X, zi );
  fe_mul( p->Y, p->Y, zi );
  fe_mul( p->T, p->X, p->Y );  /* Recompute T = X*Y since T/Z would need extra mul */
  fe_copy( p->Z, fe_one );
}

/* ========================================================================
   Conversion to AVX2 format (radix-2^25.5, 10 limbs)
   ======================================================================== */

static void
fe51_to_fe2526( fe2526 out, const fe51 in ) {
  uint8_t bytes[32];
  fe_tobytes( bytes, in );

  /* Read as 32-bit words */
  uint64_t t0 = (uint64_t)bytes[ 0] | ((uint64_t)bytes[ 1] << 8) |
                ((uint64_t)bytes[ 2] << 16) | ((uint64_t)bytes[ 3] << 24);
  uint64_t t1 = (uint64_t)bytes[ 4] | ((uint64_t)bytes[ 5] << 8) |
                ((uint64_t)bytes[ 6] << 16) | ((uint64_t)bytes[ 7] << 24);
  uint64_t t2 = (uint64_t)bytes[ 8] | ((uint64_t)bytes[ 9] << 8) |
                ((uint64_t)bytes[10] << 16) | ((uint64_t)bytes[11] << 24);
  uint64_t t3 = (uint64_t)bytes[12] | ((uint64_t)bytes[13] << 8) |
                ((uint64_t)bytes[14] << 16) | ((uint64_t)bytes[15] << 24);
  uint64_t t4 = (uint64_t)bytes[16] | ((uint64_t)bytes[17] << 8) |
                ((uint64_t)bytes[18] << 16) | ((uint64_t)bytes[19] << 24);
  uint64_t t5 = (uint64_t)bytes[20] | ((uint64_t)bytes[21] << 8) |
                ((uint64_t)bytes[22] << 16) | ((uint64_t)bytes[23] << 24);
  uint64_t t6 = (uint64_t)bytes[24] | ((uint64_t)bytes[25] << 8) |
                ((uint64_t)bytes[26] << 16) | ((uint64_t)bytes[27] << 24);
  uint64_t t7 = (uint64_t)bytes[28] | ((uint64_t)bytes[29] << 8) |
                ((uint64_t)bytes[30] << 16) | (((uint64_t)bytes[31] & 0x7F) << 24);

  /* Convert to alternating 26/25-bit limbs */
  out[0] = t0 & MASK26;
  out[1] = ((t0 >> 26) | (t1 << 6)) & MASK25;
  out[2] = ((t1 >> 19) | (t2 << 13)) & MASK26;
  out[3] = ((t2 >> 13) | (t3 << 19)) & MASK25;
  out[4] = (t3 >> 6) & MASK26;
  out[5] = t4 & MASK25;
  out[6] = ((t4 >> 25) | (t5 << 7)) & MASK26;
  out[7] = ((t5 >> 19) | (t6 << 13)) & MASK25;
  out[8] = ((t6 >> 12) | (t7 << 20)) & MASK26;
  out[9] = (t7 >> 6) & MASK25;
}

/* ========================================================================
   Output Functions
   ======================================================================== */

static void
print_fe2526( const char * name, const fe2526 f ) {
  printf( "  { 0x%07llx, 0x%07llx, 0x%07llx, 0x%07llx, 0x%07llx, "
          "0x%07llx, 0x%07llx, 0x%07llx, 0x%07llx, 0x%07llx, 0, 0 }",
          (unsigned long long)f[0], (unsigned long long)f[1],
          (unsigned long long)f[2], (unsigned long long)f[3],
          (unsigned long long)f[4], (unsigned long long)f[5],
          (unsigned long long)f[6], (unsigned long long)f[7],
          (unsigned long long)f[8], (unsigned long long)f[9] );
}

static void
print_point( const ge_p3 * p, int precomputed ) {
  fe2526 X, Y, T, Z;

  if( precomputed ) {
    /* Precomputed format: store (Y-X), (Y+X), k*T instead of X, Y, T.
       The point MUST be in affine form (Z=1) before calling this.
       We explicitly output Z=1 to ensure correctness. */
    fe51 ypx, ymx, kt;
    fe_sub( ymx, p->Y, p->X );
    fe_add( ypx, p->Y, p->X );
    fe_mul( kt, p->T, fe_k );

    fe51_to_fe2526( X, ymx );  /* X slot stores Y-X */
    fe51_to_fe2526( Y, ypx );  /* Y slot stores Y+X */
    fe51_to_fe2526( T, kt );   /* T slot stores k*T */
    fe51_to_fe2526( Z, fe_one );  /* Z is always 1 for precomputed points */
  } else {
    fe51_to_fe2526( X, p->X );
    fe51_to_fe2526( Y, p->Y );
    fe51_to_fe2526( T, p->T );
    fe51_to_fe2526( Z, p->Z );
  }

  printf( "  {\n" );
  printf( "    {{" );
  print_fe2526( "X", X );
  printf( "}},\n" );
  printf( "    {{" );
  print_fe2526( "Y", Y );
  printf( "}},\n" );
  printf( "    {{" );
  print_fe2526( "T", T );
  printf( "}},\n" );
  printf( "    {{" );
  print_fe2526( "Z", Z );
  printf( "}},\n" );
  printf( "  }" );
}

static void
print_fe2526_standalone( const char * name, const fe51 f ) {
  fe2526 out;
  fe51_to_fe2526( out, f );
  printf( "static const at_f25519_t %s[1] = {{\n", name );
  print_fe2526( "", out );
  printf( "\n}};\n\n" );
}

/* ========================================================================
   Main
   ======================================================================== */

int main( void ) {
  /* Initialize constants */
  fe_frombytes( fe_d, d_bytes );
  fe_frombytes( fe_sqrtm1, sqrtm1_bytes );
  fe_frombytes( fe_k, k_bytes );

  /* Compute base point */
  ge_p3 base;
  if( ge_frombytes( &base, base_y_bytes ) < 0 ) {
    fprintf( stderr, "Failed to decompress base point\n" );
    return 1;
  }

  /* Verify by serializing */
  uint8_t check[32];
  ge_tobytes( check, &base );

  /* Print header */
  printf( "/* Do NOT modify. This file is auto generated by gen_avx2_tables. */\n\n" );
  printf( "#ifndef HEADER_at_src_crypto_ed25519_avx2_at_curve25519_h\n" );
  printf( "#error \"Do not include this directly; use at_curve25519.h\"\n" );
  printf( "#endif\n\n" );

  /* Print base point */
  printf( "/* Ed25519 base point in extended coordinates. */\n" );
  printf( "static const at_ed25519_point_t at_ed25519_base_point_precomputed[1] = {\n" );
  printf( "  // compressed: 0x%02x", check[0] );
  for( int i = 1; i < 32; i++ ) printf( "%02x", check[i] );
  printf( "\n" );
  print_point( &base, 0 );
  printf( ",\n};\n\n" );

  /* Print low-order point Y coordinates */
  fe51 order8_y0, order8_y1;
  fe_frombytes( order8_y0, order8_y0_bytes );
  fe_frombytes( order8_y1, order8_y1_bytes );

  print_fe2526_standalone( "at_ed25519_order8_point_y0_precomputed", order8_y0 );
  print_fe2526_standalone( "at_ed25519_order8_point_y1_precomputed", order8_y1 );

  /* Generate w-NAF table: stores [1]B, [3]B, [5]B, ..., [255]B (128 points)
     These are odd multiples used in the signed sliding window method. */
  printf( "/* Ed25519 base point w-NAF table for fast scalar multiplication.\n" );
  printf( "   Table size 128 points storing odd multiples [1]B, [3]B, [5]B, ..., [255]B.\n" );
  printf( "   Points are in precomputed format: (Y-X, Y+X, k*T, Z) for fast addition.\n" );
  printf( "   Used by at_ed25519_scalar_mul_base. */\n" );
  printf( "static const at_ed25519_point_t at_ed25519_base_point_wnaf_table[128] = {\n" );

  ge_p3 table[256];

  /* Compute [1]B */
  at_memcpy( &table[1], &base, sizeof(ge_p3) );

  /* Compute [2]B */
  ge_p3_dbl( &table[2], &base );

  /* Compute [3]B, [4]B, ..., [255]B */
  for( int i = 3; i <= 255; i++ ) {
    ge_p3_add( &table[i], &table[i-1], &base );
  }

  /* Output odd multiples in precomputed format.
     IMPORTANT: Convert each point to affine form (Z=1) first, because
     the add_precomputed function assumes precomputed points have Z=1. */
  for( int i = 0; i < 128; i++ ) {
    int idx = 2*i + 1;  /* 1, 3, 5, ..., 255 */

    /* Convert to affine form (Z=1) - required for precomputed addition */
    ge_into_affine( &table[idx] );

    uint8_t compressed[32];
    ge_tobytes( compressed, &table[idx] );

    printf( "  // [%d]B compressed: 0x", idx );
    for( int j = 0; j < 32; j++ ) printf( "%02x", compressed[j] );
    printf( "\n" );

    print_point( &table[idx], 1 );  /* precomputed format */

    if( i < 127 ) printf( ",\n" );
    else printf( "\n" );
  }

  printf( "};\n\n" );

  /* Print field constants in AVX2 format */
  printf( "/* Field constants in radix-2^25.5 format. */\n" );
  print_fe2526_standalone( "at_f25519_d_precomputed", fe_d );
  print_fe2526_standalone( "at_f25519_sqrtm1_precomputed", fe_sqrtm1 );
  print_fe2526_standalone( "at_f25519_k_precomputed", fe_k );

  return 0;
}
