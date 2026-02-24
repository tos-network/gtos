#ifndef HEADER_at_src_ballet_ed25519_at_f25519_h
#error "Do not include this directly; use at_f25519.h"
#endif

#include "at_crypto_base.h"
#include "at_r43x6.h"

#define AT_F25519_ALIGN 64

/* A at_f25519_t stores a curve25519 field element in 5 ulong, aligned to 64 bytes */
struct at_f25519 {
  at_r43x6_t el __attribute__((aligned(AT_F25519_ALIGN)));
};
typedef struct at_f25519 at_f25519_t;

#include "table/at_f25519_table_avx512.c"

AT_PROTOTYPES_BEGIN

/*
 * Implementation of inline functions
 */

/* at_f25519_mul computes r = a * b, and returns r. */
AT_25519_INLINE at_f25519_t *
at_f25519_mul( at_f25519_t * r,
               at_f25519_t const * a,
               at_f25519_t const * b ) {
  AT_R43X6_MUL1_INL( r->el, a->el, b->el );
  return r;
}

/* at_f25519_sqr computes r = a^2, and returns r. */
AT_25519_INLINE at_f25519_t *
at_f25519_sqr( at_f25519_t * r,
               at_f25519_t const * a ) {
  AT_R43X6_SQR1_INL( r->el, a->el );
  return r;
}

/* at_f25519_add computes r = a + b, and returns r. */
AT_25519_INLINE at_f25519_t *
at_f25519_add( at_f25519_t * r,
               at_f25519_t const * a,
               at_f25519_t const * b ) {
  (r->el) = at_r43x6_add( (a->el), (b->el) );
  return r;
}

/* at_f25519_add computes r = a - b, and returns r. */
AT_25519_INLINE at_f25519_t *
at_f25519_sub( at_f25519_t * r,
               at_f25519_t const * a,
               at_f25519_t const * b ) {
  (r->el) = at_r43x6_fold_signed( at_r43x6_sub_fast( (a->el), (b->el) ) );
  return r;
}

/* at_f25519_add computes r = a + b, and returns r.
   Note: this does NOT reduce the result mod p.
   It can be used before mul, sqr. */
AT_25519_INLINE at_f25519_t *
at_f25519_add_nr( at_f25519_t * r,
                  at_f25519_t const * a,
                  at_f25519_t const * b ) {
  (r->el) = at_r43x6_add_fast( (a->el), (b->el) );
  return r;
}

/* at_f25519_sub computes r = a - b, and returns r.
   Note: this does NOT reduce the result mod p.
   It can be used before mul, sqr. */
AT_25519_INLINE at_f25519_t *
at_f25519_sub_nr( at_f25519_t * r,
                  at_f25519_t const * a,
                  at_f25519_t const * b ) {
  (r->el) = at_r43x6_sub_fast( (a->el), (b->el) );
  return r;
}

/* at_f25519_add computes r = -a, and returns r. */
AT_25519_INLINE at_f25519_t *
at_f25519_neg( at_f25519_t * r,
               at_f25519_t const * a ) {
  (r->el) = at_r43x6_neg( (a->el) );
  return r;
}

/* at_f25519_add computes r = a * k, k=121666, and returns r. */
AT_25519_INLINE at_f25519_t *
at_f25519_mul_121666( at_f25519_t * r,
                      AT_FN_UNUSED at_f25519_t const * a ) {
  (r->el) = at_r43x6_fold_unsigned( at_r43x6_scale_fast( 121666L, (a->el) ) );
  return r;
}

/* at_f25519_frombytes deserializes a 32-byte buffer buf into a
   at_f25519_t element r, and returns r.
   buf is in little endian form, we accept non-canonical elements
   unlike RFC 8032. */
AT_25519_INLINE at_f25519_t *
at_f25519_frombytes( at_f25519_t * r,
                     uchar const   buf[ 32 ] ) {
  ulong y0 = at_ulong_load_8_fast( buf );                         /* Bits   0- 63 */
  ulong y1 = at_ulong_load_8_fast( buf+8 );                       /* Bits  64-127 */
  ulong y2 = at_ulong_load_8_fast( buf+16 );                      /* Bits 128-191 */
  ulong y3 = at_ulong_load_8_fast( buf+24 ) & 0x7fffffffffffffff; /* Bits 192-254 */
  r->el = at_r43x6_unpack( wv( y0, y1, y2, y3 ) );
  return r;
}

/* at_f25519_tobytes serializes a at_f25519_t element a into
   a 32-byte buffer out, and returns out.
   out is in little endian form, according to RFC 8032
   (we don't output non-canonical elements). */
AT_25519_INLINE uchar *
at_f25519_tobytes( uchar               out[ 32 ],
                   at_f25519_t const * a ) {
  wv_stu( out, at_r43x6_pack( at_r43x6_mod( a->el ) ) );
  return out;
}

/* at_f25519_if sets r = a0 if cond, else r = a1, equivalent to:
   r = cond ? a0 : a1.
   Note: this is constant time. */
AT_25519_INLINE at_f25519_t *
at_f25519_if( at_f25519_t *       r,
              int const           cond, /* 0, 1 */
              at_f25519_t const * a0,
              at_f25519_t const * a1 ) {
  r->el = at_r43x6_if( -!!cond, a0->el, a1->el );
  return r;
}

/* at_f25519_swap_if swaps r1, r2 if cond, else leave them as is.
   Note: this is constant time. */
AT_25519_INLINE void
at_f25519_swap_if( at_f25519_t * restrict r1,
                   at_f25519_t * restrict r2,
                   int const              cond /* 0, 1 */ ) {
  wwl_t zero = wwl_zero();
  wwl_t m = wwl_xor(r1->el, r2->el);
  m  = wwl_if( -!!cond, m, zero );
  r1->el = wwl_xor( r1->el, m );
  r2->el = wwl_xor( r2->el, m );
}

/* at_f25519_set copies r = a, and returns r. */
AT_25519_INLINE at_f25519_t *
at_f25519_set( at_f25519_t * r,
               at_f25519_t const * a ) {
  r->el = a->el;
  return r;
}

/* at_f25519_is_zero returns 1 if a == 0, 0 otherwise. */
AT_25519_INLINE int
at_f25519_is_zero( at_f25519_t const * a ) {
  return ( ( wwl_eq( a->el, at_r43x6_zero() ) & 0xFF ) == 0xFF )
      || ( ( wwl_eq( a->el, at_r43x6_p() )    & 0xFF ) == 0xFF );
}

/*
 * Vectorized
 */

/* at_f25519_muln computes r_i = a_i * b_i */
AT_25519_INLINE void
at_f25519_mul2( at_f25519_t * r1, at_f25519_t const * a1, at_f25519_t const * b1,
                at_f25519_t * r2, at_f25519_t const * a2, at_f25519_t const * b2 ) {
  AT_R43X6_MUL2_INL( r1->el, a1->el, b1->el,
                     r2->el, a2->el, b2->el );
}

AT_25519_INLINE void
at_f25519_mul3( at_f25519_t * r1, at_f25519_t const * a1, at_f25519_t const * b1,
                at_f25519_t * r2, at_f25519_t const * a2, at_f25519_t const * b2,
                at_f25519_t * r3, at_f25519_t const * a3, at_f25519_t const * b3 ) {
  AT_R43X6_MUL3_INL( r1->el, a1->el, b1->el,
                     r2->el, a2->el, b2->el,
                     r3->el, a3->el, b3->el );
}

AT_25519_INLINE void
at_f25519_mul4( at_f25519_t * r1, at_f25519_t const * a1, at_f25519_t const * b1,
                at_f25519_t * r2, at_f25519_t const * a2, at_f25519_t const * b2,
                at_f25519_t * r3, at_f25519_t const * a3, at_f25519_t const * b3,
                at_f25519_t * r4, at_f25519_t const * a4, at_f25519_t const * b4 ) {
  AT_R43X6_MUL4_INL( r1->el, a1->el, b1->el,
                     r2->el, a2->el, b2->el,
                     r3->el, a3->el, b3->el,
                     r4->el, a4->el, b4->el );
}

/* at_f25519_sqrn computes r_i = a_i^2 */
AT_25519_INLINE void
at_f25519_sqr2( at_f25519_t * r1, at_f25519_t const * a1,
                at_f25519_t * r2, at_f25519_t const * a2 ) {
  AT_R43X6_SQR2_INL( r1->el, a1->el,
                     r2->el, a2->el );
}

AT_25519_INLINE void
at_f25519_sqr3( at_f25519_t * r1, at_f25519_t const * a1,
                at_f25519_t * r2, at_f25519_t const * a2,
                at_f25519_t * r3, at_f25519_t const * a3 ) {
  AT_R43X6_SQR3_INL( r1->el, a1->el,
                     r2->el, a2->el,
                     r3->el, a3->el );
}

AT_25519_INLINE void
at_f25519_sqr4( at_f25519_t * r1, at_f25519_t const * a1,
                at_f25519_t * r2, at_f25519_t const * a2,
                at_f25519_t * r3, at_f25519_t const * a3,
                at_f25519_t * r4, at_f25519_t const * a4 ) {
  AT_R43X6_SQR4_INL( r1->el, a1->el,
                     r2->el, a2->el,
                     r3->el, a3->el,
                     r4->el, a4->el );
}

AT_PROTOTYPES_END
