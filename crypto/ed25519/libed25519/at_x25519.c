#include "at_x25519.h"
#include "at_f25519.h"

/* AT_X25519_VECTORIZE calls mul4 instead of sqr2+mul2, and similar.
   Only useful if the underlying ops are actually vectorized and therefore
   the cost of 4 muls is <= the cost of 2 sqr + 2 mul.
   Note: Only enabled for AVX-512 IFMA which has the AT_R43X6_* macros.
   AVX-512 General (non-IFMA) uses the scalar path below. */
#define AT_X25519_VECTORIZE AT_HAS_AVX512_IFMA

/* AT_X25519_ALIGN aligns variables. */
#if AT_HAS_AVX
#define AT_X25519_ALIGN __attribute__((aligned(32)))
#else
#define AT_X25519_ALIGN
#endif

/*
 * Constant time primitives
 */

static inline int AT_FN_SENSITIVE
at_x25519_is_zero_const_time( uchar const point[ 32 ] ) {
  //TODO: this is generally done by (x)or-ing the limbs, see also RFC 7748, page 13.
  int is_zero = 1;
  for( ulong i=0UL; i<32UL; i++ ) {
    is_zero &= ( !point[ i ] );
  }
  return is_zero;
}

/* Use scalar path for:
   - No AVX-512 at all
   - AVX-512 General (non-IFMA) which uses radix-2^25.5 like AVX2
   The IFMA path below requires AT_R43X6_* macros (radix-2^43). */
#if !AT_HAS_AVX512_IFMA

static inline void AT_FN_SENSITIVE
at_x25519_montgomery_ladder( at_f25519_t *       x2,
                             at_f25519_t *       z2,
                             at_f25519_t const * x1,
                             uchar const *       secret_scalar ) {
  /* memory areas that will contain (partial) secrets and will be cleared at the end */
  at_f25519_t secret_tmp_f[4];
  int swap = 0;
  int b = 0;

  /* human-readable variables */
  at_f25519_t * x3   = &secret_tmp_f[0];
  at_f25519_t * z3   = &secret_tmp_f[1];
  at_f25519_t * tmp0 = &secret_tmp_f[2];
  at_f25519_t * tmp1 = &secret_tmp_f[3];

  at_f25519_set( x2, at_f25519_one );
  at_f25519_set( z2, at_f25519_zero );

  /* use at_f25519_add to reduce x1 mod p. this is required (we have a test). */
  at_f25519_add( x3, at_f25519_zero, x1 );
  at_f25519_set( z3, at_f25519_one );

  for( long pos=254UL; pos>=0; pos-- ) {
    b = (secret_scalar[ pos / 8L ] >> ( pos & 7L )) & 1;
    swap ^= b;
    at_f25519_swap_if( x2, x3, swap );
    at_f25519_swap_if( z2, z3, swap );
    swap = b;

    at_f25519_sub_nr( tmp0, x3,   z3   );
    at_f25519_sub_nr( tmp1, x2,   z2   );
    at_f25519_add_nr( x2,   x2,   z2   );
    at_f25519_add_nr( z2,   x3,   z3   );

#   if AT_X25519_VECTORIZE /* Note that okay to use less efficient squaring because we get it for free in unused vector lanes */
    at_f25519_mul4( z3,   tmp0, x2,
                    z2,   z2,   tmp1,
                    tmp0, tmp1, tmp1,
                    tmp1, x2,   x2   );
#   else /* Use more efficient squaring if scalar implementation */
    at_f25519_mul2( z3,   tmp0, x2,
                    z2,   z2,   tmp1 );
    at_f25519_sqr2( tmp0, tmp1,
                    tmp1, x2         );
#   endif
    at_f25519_add_nr( x3,   z3,   z2 );
    at_f25519_sub_nr( z2,   z3,   z2 );
#   if AT_X25519_VECTORIZE /* See note above */
    at_f25519_mul2( x2,   tmp1, tmp0,
                    z2,   z2,   z2   );
#   else
    at_f25519_mul(  x2,   tmp1, tmp0 );
    at_f25519_sqr(  z2,   z2         );
#   endif
    at_f25519_sub_nr( tmp1, tmp1, tmp0 );

    at_f25519_mul_121666( z3, tmp1 );

    /* z_2 = E * (AA + a24*E) where a24 = 121665.
       Since E = AA - BB, we have AA = E + BB.
       Thus: AA + a24*E = (E + BB) + 121665*E = BB + 121666*E.
       mul_121666 gives us z3 = 121666*E, so tmp0 = BB + z3 = BB + 121666*E. */
    at_f25519_add_nr( tmp0, tmp0, z3 );
#   if AT_X25519_VECTORIZE /* See note above */
    at_f25519_mul3( x3,   x3,   x3,
                    z3,   x1,   z2,
                    z2,   tmp0, tmp1 );
#   else
    at_f25519_sqr ( x3,   x3         );
    at_f25519_mul2( z3,   x1,   z2,
                    z2,   tmp1, tmp0 );
#   endif
  }

  at_f25519_swap_if( x2, x3, swap );
  at_f25519_swap_if( z2, z3, swap );

  /* Sanitize */

  at_memset_explicit( secret_tmp_f, 0, sizeof(secret_tmp_f) );
  at_memset_explicit( &b, 0, sizeof(int) );
  at_memset_explicit( &swap, 0, sizeof(int) );
}
#else

/* This is the "transposed" version of the Montgomery ladder above.
   Experimentally, this is 15-20% faster on AVX-512. */
static inline void AT_FN_SENSITIVE
at_x25519_montgomery_ladder( at_f25519_t *       x2,
                             at_f25519_t *       z2,
                             at_f25519_t const * x1,
                             uchar const *       secret_scalar ) {
  AT_R43X6_QUAD_DECL( U );
  AT_R43X6_QUAD_DECL( Q );
  AT_R43X6_QUAD_DECL( P );
  AT_R43X6_QUAD_PACK( U, at_r43x6_zero(),
                         at_r43x6_zero(),
                         at_r43x6_zero(),
                         x1->el );                      // x_1 = u, in u44
  AT_R43X6_QUAD_PACK( Q, at_r43x6_one(),                // x_2 = 1, in u44
                         at_r43x6_zero(),               // z_2 = 0, in u44
                         x1->el,                        // x_3 = u, in u44
                         at_r43x6_one() );              // z_3 = 1, in u44
  /* reduce x1 */
  AT_R43X6_QUAD_FOLD_SIGNED( U, U );
  AT_R43X6_QUAD_FOLD_SIGNED( Q, Q );
  int swap = 0;
  int k_t = 0;
  wwl_t perm;
  at_r43x6_t AA, E, F, G, H, GG;

  for( int t=254UL; t>=0; t-- ) {                       // For t = bits-1 down to 0:

    /* At this point, Q and U in u44|u44|u44|u44 */

    k_t = (secret_scalar[ t / 8L ] >> ( t & 7L )) & 1;  //   k_t = (k >> t) & 1;
    swap ^= k_t;                                        //   swap ^= k_t
    perm = wwl_if( (-swap) & 0xff, wwl( 2L,3L,0L,1L, 6L,7L,4L,5L ), wwl( 0L,1L,2L,3L, 4L,5L,6L,7L ) );
    Q03 = wwl_permute( perm, Q03 );                     //   (x_2, x_3) = cswap(swap, x_2, x_3)
    Q14 = wwl_permute( perm, Q14 );                     //   (z_2, z_3) = cswap(swap, z_2, z_3)
    Q25 = wwl_permute( perm, Q25 );
    swap = k_t;                                         //   swap = k_t

    /* These operations are exactly from the RFC but have been reordered
       slightly to make it easier to extract ILP. */

    AT_R43X6_QUAD_PERMUTE      ( P, 0,0,2,2, Q );       // A = x_2 + z_2,            P  = x_2|x_2|x_3  |x_3,   in u44|u44|u44|u44
    AT_R43X6_QUAD_PERMUTE      ( Q, 1,1,3,3, Q );       // B = x_2 - z_2,            Q  = z_2|z_2|z_3  |z_3,   in u44|u44|u44|u44
    AT_R43X6_QUAD_LANE_ADD_FAST( P, P, 1,0,1,0, P, Q ); // C = x_3 + z_3,            P  = A  |x_2|C    |x_3,   in u45|u44|u45|u44
    AT_R43X6_QUAD_LANE_SUB_FAST( P, P, 0,1,0,1, P, Q ); // D = x_3 - z_3,            P  = A  |B  |C    |D,     in u45|s44|u45|s44
    AT_R43X6_QUAD_PERMUTE      ( Q, 0,1,1,0, P );       // BB = B^2,                 P  = A  |B  |B    |A,     in u44|u44|u44|u44
    AT_R43X6_QUAD_MUL_FAST     ( P, P, Q );             // DA = D * A,               P  = AA |BB |CB   |DA,    in u62|u62|u62|u62
    AT_R43X6_QUAD_FOLD_UNSIGNED( P, P );                // DA = D * A,               P  = AA |BB |CB   |DA,    in u44|u44|u44|u44
    AT_R43X6_QUAD_PERMUTE      ( Q, 1,0,3,2, P );       // CB = C * B,               Q  = BB |AA |DA   |CB,    in u62|u62|u62|u62
    AT_R43X6_QUAD_LANE_SUB_FAST( P, P, 0,1,0,1, Q, P ); // E = AA-BB,                P  = AA |E  |CB   |CB-DA, in u62|s62|u62|s62
    AT_R43X6_QUAD_LANE_ADD_FAST( P, P, 0,0,1,0, P, Q ); //                           P  = AA |E  |DA+CB|CB-DA, in u62|s62|u63|s62
    AT_R43X6_QUAD_LANE_IF      ( Q, 0,1,1,0, P, Q );    //                           Q  = BB |E  |DA+CB|CB,    in u62|u44|u44|u62
    AT_R43X6_QUAD_LANE_IF      ( Q, 0,0,0,1, U, Q );    // x_3 = (DA + CB)^2,        Q  = BB |E  |DA+CB|x_1,   in u62|u44|u44|u44
    AT_R43X6_QUAD_UNPACK       ( AA, E, F, G, P );
    H  = at_r43x6_add_fast( AA, at_r43x6_scale_fast( 121665L, E ) ); //              H  = AA + a24 * E,        in u60
    GG = at_r43x6_sqr_fast( G );                        //                           GG = (DA - CB)^2,         in u61
    AT_R43X6_QUAD_PACK         ( P, AA, H, F, GG );     // z_2 = E * (AA + a24 * E), P  = AA |H  |DA+CB|GG,    in u44|u60|u44|u61
    AT_R43X6_QUAD_FOLD_UNSIGNED( P, P );                //                           P  = AA |H  |DA+CB|GG,    in u44|u44|u44|u44
    AT_R43X6_QUAD_MUL_FAST     ( P, P, Q );             // z_3 = x_1 * (DA - CB)^2,  Q  = x_2|z_2|x_3  |z_3,   in u62|u62|u62|u62
    AT_R43X6_QUAD_FOLD_UNSIGNED( Q, P    );             //                           Q  = x_2|z_2|x_3  |z_3,   in u44|u44|u44|u44
  }

  /* At this point, Q in u44|u44|u44|u44 */
  perm = wwl_if( (-swap) & 0xff, wwl( 2L,3L,0L,1L, 6L,7L,4L,5L ), wwl( 0L,1L,2L,3L, 4L,5L,6L,7L ) );
  Q03 = wwl_permute( perm, Q03 );                       // (x_2, x_3) = cswap(swap, x_2, x_3)
  Q14 = wwl_permute( perm, Q14 );                       // (z_2, z_3) = cswap(swap, z_2, z_3)
  Q25 = wwl_permute( perm, Q25 );

  AT_R43X6_QUAD_UNPACK( x2->el, z2->el, E, F, Q );

  /* Sanitize */

  at_memset_explicit( &P03,  0, sizeof(wwl_t) );
  at_memset_explicit( &P14,  0, sizeof(wwl_t) );
  at_memset_explicit( &P25,  0, sizeof(wwl_t) );
  at_memset_explicit( &U03,  0, sizeof(wwl_t) );
  at_memset_explicit( &U14,  0, sizeof(wwl_t) );
  at_memset_explicit( &U25,  0, sizeof(wwl_t) );
  at_memset_explicit( &Q03,  0, sizeof(wwl_t) );
  at_memset_explicit( &Q14,  0, sizeof(wwl_t) );
  at_memset_explicit( &Q25,  0, sizeof(wwl_t) );
  at_memset_explicit( &AA,   0, sizeof(wwl_t) );
  at_memset_explicit( &E,    0, sizeof(wwl_t) );
  at_memset_explicit( &F,    0, sizeof(wwl_t) );
  at_memset_explicit( &G,    0, sizeof(wwl_t) );
  at_memset_explicit( &H,    0, sizeof(wwl_t) );
  at_memset_explicit( &GG,   0, sizeof(wwl_t) );
  at_memset_explicit( &perm, 0, sizeof(wwl_t) );
  at_memset_explicit( &swap, 0, sizeof(int) );
  at_memset_explicit( &k_t,  0, sizeof(int) );

}
#endif

/*
 * X25519 Protocol
 */

static inline void AT_FN_SENSITIVE
at_x25519_scalar_mul_const_time( uchar               out[ 32 ],
                                 uchar const *       secret_scalar,
                                 at_f25519_t const * point_x ) {
  at_f25519_t x2[1], z2[1];

  at_x25519_montgomery_ladder( x2, z2, point_x, secret_scalar );

  at_f25519_inv( z2, z2 );
  at_f25519_mul( x2, x2, z2 );

  at_f25519_tobytes( out, x2 );
}

static const uchar at_x25519_basepoint[ 32 ] AT_X25519_ALIGN = { 9 };

uchar * AT_FN_SENSITIVE
at_x25519_public( uchar       self_public_key [ 32 ],
                  uchar const self_private_key[ 32 ] ) {
  /* IETF RFC 7748 Section 4.1 (page 3) */
  return at_x25519_exchange( self_public_key, self_private_key, at_x25519_basepoint );
}

uchar * AT_FN_SENSITIVE
at_x25519_exchange( uchar       shared_secret   [ 32 ],
                    uchar const self_private_key[ 32 ],
                    uchar const peer_public_key [ 32 ] ) {

  /* Memory areas that will contain secrets */
  uchar secret_scalar[ 32UL ] AT_X25519_ALIGN;

  /* Public local variables */
  at_f25519_t peer_public_key_point_u[1];

  //  RFC 7748 - Elliptic Curves for Security
  //
  //  5. The X25519 and X448 Functions
  //
  //  The "X25519" and "X448" functions perform scalar multiplication on
  //  the Montgomery form of the above curves.  (This is used when
  //  implementing Diffie-Hellman.)  The functions take a scalar and a
  //  u-coordinate as inputs and produce a u-coordinate as output.
  //  Although the functions work internally with integers, the inputs and
  //  outputs are 32-byte strings (for X25519) or 56-byte strings (for
  //  X448) and this specification defines their encoding.

  //  The u-coordinates are elements of the underlying field GF(2^255 - 19)
  //  or GF(2^448 - 2^224 - 1) and are encoded as an array of bytes, u, in
  //  little-endian order such that u[0] + 256*u[1] + 256^2*u[2] + ... +
  //  256^(n-1)*u[n-1] is congruent to the value modulo p and u[n-1] is
  //  minimal.  When receiving such an array, implementations of X25519
  //  (but not X448) MUST mask the most significant bit in the final byte.
  //  This is done to preserve compatibility with point formats that
  //  reserve the sign bit for use in other protocols and to increase
  //  resistance to implementation fingerprinting.

  //  Implementations MUST accept non-canonical values and process them as
  //  if they had been reduced modulo the field prime.  The non-canonical
  //  values are 2^255 - 19 through 2^255 - 1 for X25519 and 2^448 - 2^224
  //  - 1 through 2^448 - 1 for X448.

  /* From the text above:
     1. When receiving such an array, implementations of X25519 [...]
        MUST mask the most significant bit in the final byte
        >> this is done by at_f25519_frombytes
     2. Implementations MUST accept non-canonical values
        >> no extra check needed */
  at_f25519_frombytes( peer_public_key_point_u, peer_public_key );

  //  Scalars are assumed to be randomly generated bytes.  For X25519, in
  //  order to decode 32 random bytes as an integer scalar, set the three
  //  least significant bits of the first byte and the most significant bit
  //  of the last to zero, set the second most significant bit of the last
  //  byte to 1 and, finally, decode as little-endian.  This means that the
  //  resulting integer is of the form 2^254 plus eight times a value
  //  between 0 and 2^251 - 1 (inclusive).  Likewise, for X448, set the two
  //  least significant bits of the first byte to 0, and the most
  //  significant bit of the last byte to 1.  This means that the resulting
  //  integer is of the form 2^447 plus four times a value between 0 and
  //  2^445 - 1 (inclusive).

  /* decodeScalar25519
     note: e need to copy the private key, because we need to sanitize it. */
  at_memcpy( secret_scalar, self_private_key, 32UL );
  secret_scalar[ 0] &= (uchar)0xF8;
  secret_scalar[31] &= (uchar)0x7F;
  secret_scalar[31] |= (uchar)0x40;

  at_x25519_scalar_mul_const_time( shared_secret, secret_scalar, peer_public_key_point_u );

  /* Sanitize */
  at_memset_explicit( secret_scalar, 0, 32UL );

  /* Reject low order points */
  if( AT_UNLIKELY( at_x25519_is_zero_const_time( shared_secret ) ) ) {
    return NULL;
  }

  return shared_secret;
}