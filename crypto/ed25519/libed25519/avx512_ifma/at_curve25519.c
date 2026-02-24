#include "../at_curve25519.h"
#include "./at_r43x6_ge.h"

/*
 * Add
 */

/* at_ed25519_point_add_with_opts computes r = a + b, and returns r.

   https://eprint.iacr.org/2008/522
   Sec 4.2, 4-Processor Montgomery addition and doubling.

   This implementation includes several optional optimizations
   that are used for speeding up scalar multiplication:

   - b_Z_is_one, if b->Z == 1 (affine, or decompressed), we can skip 1mul

   - b_is_precomputed, since the scalar mul loop typically accumulates
     points from a table, we can pre-compute kT into the table points and
     therefore skip 1mul in during the loop.

   - skip_last_mul, since dbl can be computed with just (X, Y, Z)
     and doesn't need T, we can skip the last 4 mul and selectively
     compute (X, Y, Z) or (X, Y, Z, T) during the scalar mul loop.
 */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_add_with_opts( at_ed25519_point_t *       r,
                                at_ed25519_point_t const * a,
                                at_ed25519_point_t const * b,
                                AT_PARAM_UNUSED int const b_Z_is_one,
                                int const b_is_precomputed,
                                AT_PARAM_UNUSED int const skip_last_mul ) {

  if( b_is_precomputed ) {
    at_ed25519_point_t tmp[2];
    AT_R43X6_GE_ADD_TABLE_ALT( r->P, a->P, b->P, tmp[0].P, tmp[1].P );
  } else {
    AT_R43X6_GE_ADD( r->P, a->P, b->P );
  }
  return r;
}

/* at_ed25519_point_add computes r = a + b, and returns r. */
at_ed25519_point_t *
at_ed25519_point_add( at_ed25519_point_t *       r,
                      at_ed25519_point_t const * a,
                      at_ed25519_point_t const * b ) {
  return at_ed25519_point_add_with_opts( r, a, b, 0, 0, 0 );
}

/* at_ed25519_point_add_final_mul computes just the final mul step in point add.
   See at_ed25519_point_add_with_opts. */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_add_final_mul( at_ed25519_point_t * restrict r,
                                at_ed25519_point_t const *    a ) {
  at_ed25519_point_set( r, a );
  return r;
}

/* at_ed25519_point_add_final_mul_projective computes just the final mul step
   in point add, assuming the result is projective (X, Y, Z), i.e. ignoring T.
   This is useful because dbl only needs (X, Y, Z) in input, so we can save 1mul.
   See at_ed25519_point_add_with_opts. */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_add_final_mul_projective( at_ed25519_point_t * restrict r,
                                           at_ed25519_point_t const *    a ) {
  at_ed25519_point_set( r, a );
  return r;
}

/*
 * Sub
 */

/* at_ed25519_point_sub sets r = -a. */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_neg_precomputed( at_ed25519_point_t *       r,
                      at_ed25519_point_t const * a ) {
  /* use p instead of zero to avoid mod reduction */
  AT_R43X6_QUAD_DECL( _p );
  _p03 = wwl( 8796093022189L, 8796093022189L, 8796093022189L, 8796093022189L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L );
  _p14 = wwl( 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L );
  _p25 = wwl( 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 1099511627775L, 1099511627775L, 1099511627775L, 1099511627775L );
  AT_R43X6_QUAD_LANE_SUB_FAST( r->P, a->P, 0,0,0,1, _p, a->P );
  AT_R43X6_QUAD_PERMUTE      ( r->P, 1,0,2,3, r->P );
  return r;
}

/* at_ed25519_point_sub_with_opts computes r = a - b, and returns r.
   This is like at_ed25519_point_add_with_opts, replacing:
   - b->X => -b->X
   - b->T => -b->T
   See at_ed25519_point_add_with_opts for details.
 */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_sub_with_opts( at_ed25519_point_t *       r,
                                at_ed25519_point_t const * a,
                                at_ed25519_point_t const * b,
                                int const b_Z_is_one,
                                int const b_is_precomputed,
                                int const skip_last_mul ) {

  at_ed25519_point_t neg[1];
  if (b_is_precomputed) {
    at_ed25519_point_neg_precomputed( neg, b );
  } else {
    at_ed25519_point_neg( neg, b );
  }
  return at_ed25519_point_add_with_opts( r, a, neg, b_Z_is_one, b_is_precomputed, skip_last_mul );
}

/* at_ed25519_point_sub computes r = a - b, and returns r. */
at_ed25519_point_t *
at_ed25519_point_sub( at_ed25519_point_t *       r,
                      at_ed25519_point_t const * a,
                      at_ed25519_point_t const * b ) {
  return at_ed25519_point_sub_with_opts( r, a, b, 0, 0, 0 );
}

/*
 * Dbl
 */

/* Dedicated dbl
   https://eprint.iacr.org/2008/522
   Sec 4.4.
   This uses sqr instead of mul.

   TODO: use the same iface with_opts?
  */

AT_25519_INLINE at_ed25519_point_t *
at_ed25519_partial_dbl( at_ed25519_point_t *       r,
                        at_ed25519_point_t const * a ) {
  AT_R43X6_GE_DBL( r->P, a->P );
  return r;
}

at_ed25519_point_t *
at_ed25519_point_dbl( at_ed25519_point_t *       r,
                      at_ed25519_point_t const * a ) {
  AT_R43X6_GE_DBL( r->P, a->P );
  return r;
}

/*
 * Ser/de
 */

int
at_ed25519_point_frombytes_2x( at_ed25519_point_t * r1,
                               uchar const          buf1[ 32 ],
                               at_ed25519_point_t * r2,
                               uchar const          buf2[ 32 ] ) {
  //TODO: consider unifying code with ref
  return AT_R43X6_GE_DECODE2( r1->P, buf1, r2->P, buf2 );
}

/*
  Affine (only for init(), can be slow)
*/
at_ed25519_point_t *
at_curve25519_affine_frombytes( at_ed25519_point_t * r,
                                uchar const          _x[ 32 ],
                                uchar const          _y[ 32 ] ) {
  at_f25519_t x[1], y[1], z[1], t[1];
  at_f25519_frombytes( x, _x );
  at_f25519_frombytes( y, _y );
  at_f25519_set( z, at_f25519_one );
  at_f25519_mul( t, x, y );
  AT_R43X6_QUAD_PACK( r->P, x->el, y->el, z->el, t->el );
  return r;
}

at_ed25519_point_t *
at_curve25519_into_affine( at_ed25519_point_t * r ) {
  at_f25519_t x[1], y[1], z[1], t[1];
  AT_R43X6_QUAD_UNPACK( x->el, y->el, z->el, t->el, r->P );
  at_f25519_inv( z, z );
  at_f25519_mul( x, x, z );
  at_f25519_mul( y, y, z );
  at_f25519_set( z, at_f25519_one );
  at_f25519_mul( t, x, y );
  AT_R43X6_QUAD_PACK( r->P, x->el, y->el, z->el, t->el );
  return r;
}
