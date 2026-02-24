#ifndef HEADER_at_src_ballet_ed25519_at_curve25519_h
#error "Do not include this directly; use at_curve25519.h"
#endif

/* at_curve25519.h provides the public Curve25519 API.

   Most operations in this API should be assumed to take a variable
   amount of time depending on inputs.  (And thus should not be exposed
   to secret data).

   Const time operations are made explicit, see at_curve25519_secure.c */

#include "../../at_ballet_base.h"
#include "../at_f25519.h"
#include "../at_curve25519_scalar.h"
#include "./at_r43x6_ge.h"

/* struct at_curve25519_edwards (aka at_curve25519_edwards_t) represents
   a point in Extended Twisted Edwards Coordinates.
   https://eprint.iacr.org/2008/522 */
struct at_curve25519_edwards {
  AT_R43X6_QUAD_DECL( P ) __attribute__((aligned(AT_F25519_ALIGN)));
};
typedef struct at_curve25519_edwards at_curve25519_edwards_t;

typedef at_curve25519_edwards_t at_ed25519_point_t;
typedef at_curve25519_edwards_t at_ristretto255_point_t;

#include "../table/at_curve25519_table_avx512.c"

AT_PROTOTYPES_BEGIN

/* at_ed25519_point_set sets r = 0 (point at infinity). */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_set_zero( at_ed25519_point_t * r ) {
  AT_R43X6_GE_ZERO( r->P );
  return r;
}

/* at_ed25519_point_set_zero_precomputed sets r = 0 (point at infinity). */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_set_zero_precomputed( at_ed25519_point_t * r ) {
  r->P03 = wwl( 1L,1L,1L,0L, 0L,0L,0L,0L ); r->P14 = wwl_zero(); r->P25 = wwl_zero();
  return r;
}

/* at_ed25519_point_set sets r = a. */
AT_25519_INLINE at_ed25519_point_t * AT_FN_NO_ASAN
at_ed25519_point_set( at_ed25519_point_t *       r,
                      at_ed25519_point_t const * a ) {
  r->P03 = a->P03;
  r->P14 = a->P14;
  r->P25 = a->P25;
  return r;
}

/* at_ed25519_point_from sets r = (x : y : z : t). */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_from( at_ed25519_point_t * r,
                       at_f25519_t const *  x,
                       at_f25519_t const *  y,
                       at_f25519_t const *  z,
                       at_f25519_t const *  t ) {
  AT_R43X6_QUAD_PACK( r->P, x->el, y->el, z->el, t->el );
  return r;
}

/* at_ed25519_point_from sets (x : y : z : t) = a. */
AT_25519_INLINE void
at_ed25519_point_to( at_f25519_t *  x,
                     at_f25519_t *  y,
                     at_f25519_t *  z,
                     at_f25519_t *  t,
                     at_ed25519_point_t const * a ) {
  AT_R43X6_QUAD_UNPACK( x->el, y->el, z->el, t->el, a->P );
}

/* at_ed25519_point_dbln computes r = 2^n a, and returns r.
   More efficient than n at_ed25519_point_add. */
AT_25519_INLINE at_ed25519_point_t * AT_FN_NO_ASAN
at_ed25519_point_dbln( at_ed25519_point_t *       r,
                       at_ed25519_point_t const * a,
                       int                        n ) {
  AT_R43X6_GE_DBL( r->P, a->P );
  for( uchar i=1; i<n; i++ ) {
    AT_R43X6_GE_DBL( r->P, r->P );
  }
  return r;
}

/* at_ed25519_point_sub sets r = -a. */
AT_25519_INLINE at_ed25519_point_t *
at_ed25519_point_neg( at_ed25519_point_t *       r,
                      at_ed25519_point_t const * a ) {
  /* use p instead of zero to avoid mod reduction */
  AT_R43X6_QUAD_DECL( _p );
  _p03 = wwl( 8796093022189L, 8796093022189L, 8796093022189L, 8796093022189L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L );
  _p14 = wwl( 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L );
  _p25 = wwl( 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 1099511627775L, 1099511627775L, 1099511627775L, 1099511627775L );
  AT_R43X6_QUAD_LANE_SUB_FAST( r->P, a->P, 1,0,0,1, _p, a->P );
  AT_R43X6_QUAD_FOLD_UNSIGNED( r->P, r->P );
  return r;
}

/* at_ed25519_point_is_zero returns 1 if a == 0 (point at infinity), 0 otherwise. */
AT_25519_INLINE int
at_ed25519_point_is_zero( at_ed25519_point_t const * a ) {
  at_ed25519_point_t zero[1];
  at_ed25519_point_set_zero( zero );
  return AT_R43X6_GE_IS_EQ( a->P, zero->P );
}

/* at_ed25519_point_eq returns 1 if a == b, 0 otherwise. */
AT_25519_INLINE int
at_ed25519_point_eq( at_ed25519_point_t const * a,
                     at_ed25519_point_t const * b ) {
  return AT_R43X6_GE_IS_EQ( a->P, b->P );
}

/* at_ed25519_point_eq returns 1 if a == b, 0 otherwise.
   b is a point with Z==1, e.g. a decompressed point. */
AT_25519_INLINE int
at_ed25519_point_eq_z1( at_ed25519_point_t const * a,
                        at_ed25519_point_t const * b ) { /* b.Z == 1, e.g. a decompressed point */
  return at_ed25519_point_eq( a, b );
}

AT_25519_INLINE void
at_curve25519_into_precomputed( at_ed25519_point_t * r ) {
  AT_R43X6_QUAD_DECL         ( _ta );
  AT_R43X6_QUAD_PERMUTE      ( _ta, 1,0,2,3, r->P );            /* _ta = (Y1,   X1,   Z1,   T1   ), s61|s61|s61|s61 */
  AT_R43X6_QUAD_LANE_SUB_FAST( _ta, _ta, 1,0,0,0, _ta, r->P );  /* _ta = (Y1-X1,X1,   Z1,   T1   ), s62|s61|s61|s61 */
  AT_R43X6_QUAD_LANE_ADD_FAST( _ta, _ta, 0,1,0,0, _ta, r->P );  /* _ta = (Y1-X1,Y1+X1,Z1,   T1   ), s62|s62|s61|s61 */
  AT_R43X6_QUAD_FOLD_SIGNED  ( r->P, _ta );                     /*   r = (Y1-X1,Y1+X1,Z1,   T1   ), u44|u44|u44|u44 */

  AT_R43X6_QUAD_DECL         ( _1112d );
  AT_R43X6_QUAD_1112d        ( _1112d );
  AT_R43X6_QUAD_MUL_FAST     ( r->P, r->P, _1112d );
  AT_R43X6_QUAD_FOLD_UNSIGNED( r->P, r->P );
}

AT_PROTOTYPES_END
