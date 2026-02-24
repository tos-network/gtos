#ifndef HEADER_at_src_crypto_ed25519_avx2_at_f25519_h
#define HEADER_at_src_crypto_ed25519_avx2_at_f25519_h

/* AVX2 field element wrapper for curve25519.

   This provides the same interface as the reference implementation but
   uses AVX2 SIMD instructions for acceleration. The scalar operations
   work on single field elements, while the vectorized operations (mul4,
   sqr4, etc.) process 4 elements in parallel using the at_r2526x10_t type.

   This is a self-contained AVX2 implementation that can be used independently
   or integrated via the at_f25519.h dispatcher. */

#if AT_HAS_AVX && !AT_HAS_AVX512_IFMA

#include "at_r2526x10.h"
#include <stdint.h>

#define AT_25519_INLINE static inline
#define AT_F25519_ALIGN 32

/* A at_f25519_t stores a curve25519 field element in reduced radix form.
   For AVX2, we use 10 limbs with alternating 26/25 bit sizes, stored in
   12 uint64_t slots (10 limbs + 2 padding for alignment). */
struct at_f25519 {
  uint64_t el[12] __attribute__((aligned(AT_F25519_ALIGN)));
};
typedef struct at_f25519 at_f25519_t;

/* ========================================================================
   Field Constants (Radix 2^25.5, 10 limbs)

   Simple constants (0, 1, 2) are defined directly.
   Complex constants (d, sqrtm1, etc.) are initialized at runtime via
   at_f25519_frombytes() in at_ed25519_avx2_init_constants().
   ======================================================================== */

/* 0 in reduced radix form */
static const at_f25519_t at_f25519_zero[1] = {{
  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
}};

/* 1 in reduced radix form */
static const at_f25519_t at_f25519_one[1] = {{
  { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
}};

/* 2 in reduced radix form */
static const at_f25519_t at_f25519_two[1] = {{
  { 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
}};

/* -1 mod p = p - 1 = 2^255 - 20 in reduced radix form
   In 10 limbs with alternating 26/25 bits:
   limb[0] = (p-1) mod 2^26 = 2^26 - 20 = 0x3FFFFEC
   limb[1..9] = all 1s in their respective bit widths */
static const at_f25519_t at_f25519_minus_one[1] = {{
  { 0x3FFFFEC, 0x1FFFFFF, 0x3FFFFFF, 0x1FFFFFF, 0x3FFFFFF,
    0x1FFFFFF, 0x3FFFFFF, 0x1FFFFFF, 0x3FFFFFF, 0x1FFFFFF, 0, 0 }
}};

/* Complex constants - initialized at runtime */
static at_f25519_t at_f25519_d_storage[1];
static at_f25519_t at_f25519_sqrtm1_storage[1];
static at_f25519_t at_f25519_k_storage[1];

#define at_f25519_d at_f25519_d_storage
#define at_f25519_sqrtm1 at_f25519_sqrtm1_storage
#define at_f25519_k at_f25519_k_storage

/* Byte constants for runtime initialization */
static const uchar at_f25519_d_bytes[32] = {
  0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
  0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
  0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
  0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52
};

static const uchar at_f25519_sqrtm1_bytes[32] = {
  0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
  0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
  0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
  0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b
};

/* k = 2d constant for Ed25519 */
static const uchar at_f25519_k_bytes[32] = {
  0x59, 0xf1, 0xb2, 0x26, 0x94, 0x9b, 0xd6, 0xeb,
  0x56, 0xb1, 0x83, 0x82, 0x9a, 0x14, 0xe0, 0x00,
  0x30, 0xd1, 0xf3, 0xee, 0xf2, 0x80, 0x8e, 0x19,
  0xe7, 0xfc, 0xdf, 0x56, 0xdc, 0xd9, 0x06, 0x24
};

AT_PROTOTYPES_BEGIN

/* ========================================================================
   Internal Helpers
   ======================================================================== */

/* Masks for the alternating radix */
#define AT_F25519_MASK26 ((uint64_t)0x3FFFFFF)
#define AT_F25519_MASK25 ((uint64_t)0x1FFFFFF)

/* at_f25519_carry performs carry propagation on a scalar element. */
static inline void
at_f25519_carry( at_f25519_t * r ) {
  uint64_t c;

  c = r->el[0] >> 26; r->el[0] &= AT_F25519_MASK26; r->el[1] += c;
  c = r->el[1] >> 25; r->el[1] &= AT_F25519_MASK25; r->el[2] += c;
  c = r->el[2] >> 26; r->el[2] &= AT_F25519_MASK26; r->el[3] += c;
  c = r->el[3] >> 25; r->el[3] &= AT_F25519_MASK25; r->el[4] += c;
  c = r->el[4] >> 26; r->el[4] &= AT_F25519_MASK26; r->el[5] += c;
  c = r->el[5] >> 25; r->el[5] &= AT_F25519_MASK25; r->el[6] += c;
  c = r->el[6] >> 26; r->el[6] &= AT_F25519_MASK26; r->el[7] += c;
  c = r->el[7] >> 25; r->el[7] &= AT_F25519_MASK25; r->el[8] += c;
  c = r->el[8] >> 26; r->el[8] &= AT_F25519_MASK26; r->el[9] += c;
  c = r->el[9] >> 25; r->el[9] &= AT_F25519_MASK25; r->el[0] += 19 * c;
  c = r->el[0] >> 26; r->el[0] &= AT_F25519_MASK26; r->el[1] += c;
}

/* ========================================================================
   Scalar Field Operations
   ======================================================================== */

/* at_f25519_mul computes r = a * b, and returns r. */
AT_25519_INLINE at_f25519_t *
at_f25519_mul( at_f25519_t *       r,
               at_f25519_t const * a,
               at_f25519_t const * b ) {
  /* Schoolbook multiplication with delayed carry */
  uint64_t const * ae = a->el;
  uint64_t const * be = b->el;
  uint64_t * re = r->el;

  /* Pre-multiply b coefficients by 19 for reduction */
  uint64_t b1_19 = 19 * be[1];
  uint64_t b2_19 = 19 * be[2];
  uint64_t b3_19 = 19 * be[3];
  uint64_t b4_19 = 19 * be[4];
  uint64_t b5_19 = 19 * be[5];
  uint64_t b6_19 = 19 * be[6];
  uint64_t b7_19 = 19 * be[7];
  uint64_t b8_19 = 19 * be[8];
  uint64_t b9_19 = 19 * be[9];

  /* For odd indices, we need to double when both are odd */
  uint64_t a1_2 = 2 * ae[1];
  uint64_t a3_2 = 2 * ae[3];
  uint64_t a5_2 = 2 * ae[5];
  uint64_t a7_2 = 2 * ae[7];
  uint64_t a9_2 = 2 * ae[9];

  __uint128_t c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;

  c0 = (__uint128_t)ae[0]*be[0] + (__uint128_t)a1_2*b9_19 + (__uint128_t)ae[2]*b8_19 +
       (__uint128_t)a3_2*b7_19 + (__uint128_t)ae[4]*b6_19 + (__uint128_t)a5_2*b5_19 +
       (__uint128_t)ae[6]*b4_19 + (__uint128_t)a7_2*b3_19 + (__uint128_t)ae[8]*b2_19 +
       (__uint128_t)a9_2*b1_19;

  c1 = (__uint128_t)ae[0]*be[1] + (__uint128_t)ae[1]*be[0] + (__uint128_t)ae[2]*b9_19 +
       (__uint128_t)ae[3]*b8_19 + (__uint128_t)ae[4]*b7_19 + (__uint128_t)ae[5]*b6_19 +
       (__uint128_t)ae[6]*b5_19 + (__uint128_t)ae[7]*b4_19 + (__uint128_t)ae[8]*b3_19 +
       (__uint128_t)ae[9]*b2_19;

  c2 = (__uint128_t)ae[0]*be[2] + (__uint128_t)a1_2*be[1] + (__uint128_t)ae[2]*be[0] +
       (__uint128_t)a3_2*b9_19 + (__uint128_t)ae[4]*b8_19 + (__uint128_t)a5_2*b7_19 +
       (__uint128_t)ae[6]*b6_19 + (__uint128_t)a7_2*b5_19 + (__uint128_t)ae[8]*b4_19 +
       (__uint128_t)a9_2*b3_19;

  c3 = (__uint128_t)ae[0]*be[3] + (__uint128_t)ae[1]*be[2] + (__uint128_t)ae[2]*be[1] +
       (__uint128_t)ae[3]*be[0] + (__uint128_t)ae[4]*b9_19 + (__uint128_t)ae[5]*b8_19 +
       (__uint128_t)ae[6]*b7_19 + (__uint128_t)ae[7]*b6_19 + (__uint128_t)ae[8]*b5_19 +
       (__uint128_t)ae[9]*b4_19;

  c4 = (__uint128_t)ae[0]*be[4] + (__uint128_t)a1_2*be[3] + (__uint128_t)ae[2]*be[2] +
       (__uint128_t)a3_2*be[1] + (__uint128_t)ae[4]*be[0] + (__uint128_t)a5_2*b9_19 +
       (__uint128_t)ae[6]*b8_19 + (__uint128_t)a7_2*b7_19 + (__uint128_t)ae[8]*b6_19 +
       (__uint128_t)a9_2*b5_19;

  c5 = (__uint128_t)ae[0]*be[5] + (__uint128_t)ae[1]*be[4] + (__uint128_t)ae[2]*be[3] +
       (__uint128_t)ae[3]*be[2] + (__uint128_t)ae[4]*be[1] + (__uint128_t)ae[5]*be[0] +
       (__uint128_t)ae[6]*b9_19 + (__uint128_t)ae[7]*b8_19 + (__uint128_t)ae[8]*b7_19 +
       (__uint128_t)ae[9]*b6_19;

  c6 = (__uint128_t)ae[0]*be[6] + (__uint128_t)a1_2*be[5] + (__uint128_t)ae[2]*be[4] +
       (__uint128_t)a3_2*be[3] + (__uint128_t)ae[4]*be[2] + (__uint128_t)a5_2*be[1] +
       (__uint128_t)ae[6]*be[0] + (__uint128_t)a7_2*b9_19 + (__uint128_t)ae[8]*b8_19 +
       (__uint128_t)a9_2*b7_19;

  c7 = (__uint128_t)ae[0]*be[7] + (__uint128_t)ae[1]*be[6] + (__uint128_t)ae[2]*be[5] +
       (__uint128_t)ae[3]*be[4] + (__uint128_t)ae[4]*be[3] + (__uint128_t)ae[5]*be[2] +
       (__uint128_t)ae[6]*be[1] + (__uint128_t)ae[7]*be[0] + (__uint128_t)ae[8]*b9_19 +
       (__uint128_t)ae[9]*b8_19;

  c8 = (__uint128_t)ae[0]*be[8] + (__uint128_t)a1_2*be[7] + (__uint128_t)ae[2]*be[6] +
       (__uint128_t)a3_2*be[5] + (__uint128_t)ae[4]*be[4] + (__uint128_t)a5_2*be[3] +
       (__uint128_t)ae[6]*be[2] + (__uint128_t)a7_2*be[1] + (__uint128_t)ae[8]*be[0] +
       (__uint128_t)a9_2*b9_19;

  c9 = (__uint128_t)ae[0]*be[9] + (__uint128_t)ae[1]*be[8] + (__uint128_t)ae[2]*be[7] +
       (__uint128_t)ae[3]*be[6] + (__uint128_t)ae[4]*be[5] + (__uint128_t)ae[5]*be[4] +
       (__uint128_t)ae[6]*be[3] + (__uint128_t)ae[7]*be[2] + (__uint128_t)ae[8]*be[1] +
       (__uint128_t)ae[9]*be[0];

  /* Carry propagation */
  uint64_t carry;
  re[0] = (uint64_t)c0 & AT_F25519_MASK26; carry = (uint64_t)(c0 >> 26);
  c1 += carry;
  re[1] = (uint64_t)c1 & AT_F25519_MASK25; carry = (uint64_t)(c1 >> 25);
  c2 += carry;
  re[2] = (uint64_t)c2 & AT_F25519_MASK26; carry = (uint64_t)(c2 >> 26);
  c3 += carry;
  re[3] = (uint64_t)c3 & AT_F25519_MASK25; carry = (uint64_t)(c3 >> 25);
  c4 += carry;
  re[4] = (uint64_t)c4 & AT_F25519_MASK26; carry = (uint64_t)(c4 >> 26);
  c5 += carry;
  re[5] = (uint64_t)c5 & AT_F25519_MASK25; carry = (uint64_t)(c5 >> 25);
  c6 += carry;
  re[6] = (uint64_t)c6 & AT_F25519_MASK26; carry = (uint64_t)(c6 >> 26);
  c7 += carry;
  re[7] = (uint64_t)c7 & AT_F25519_MASK25; carry = (uint64_t)(c7 >> 25);
  c8 += carry;
  re[8] = (uint64_t)c8 & AT_F25519_MASK26; carry = (uint64_t)(c8 >> 26);
  c9 += carry;
  re[9] = (uint64_t)c9 & AT_F25519_MASK25; carry = (uint64_t)(c9 >> 25);
  re[0] += 19 * carry;
  carry = re[0] >> 26; re[0] &= AT_F25519_MASK26; re[1] += carry;

  return r;
}

/* at_f25519_sqr computes r = a^2, and returns r. */
AT_25519_INLINE at_f25519_t *
at_f25519_sqr( at_f25519_t *       r,
               at_f25519_t const * a ) {
  return at_f25519_mul( r, a, a );
}

/* at_f25519_add computes r = a + b, and returns r. */
AT_25519_INLINE at_f25519_t *
at_f25519_add( at_f25519_t *       r,
               at_f25519_t const * a,
               at_f25519_t const * b ) {
  for( int i = 0; i < 10; i++ ) {
    r->el[i] = a->el[i] + b->el[i];
  }
  at_f25519_carry( r );
  return r;
}

/* at_f25519_sub computes r = a - b, and returns r.
   Add 2p to avoid underflow. Pattern: even limbs are 26-bit, odd are 25-bit.
   limb[0]: 0x7FFFFDA = 2*(2^26 - 19) = 2^27 - 38 (special for -19)
   limb[even]: 0x7FFFFFE = 2*(2^26 - 1) for 26-bit limbs
   limb[odd]:  0x3FFFFFE = 2*(2^25 - 1) for 25-bit limbs */
AT_25519_INLINE at_f25519_t *
at_f25519_sub( at_f25519_t *       r,
               at_f25519_t const * a,
               at_f25519_t const * b ) {
  r->el[0] = a->el[0] + 0x7FFFFDA - b->el[0];  /* 26-bit, -19 adjust */
  r->el[1] = a->el[1] + 0x3FFFFFE - b->el[1];  /* 25-bit */
  r->el[2] = a->el[2] + 0x7FFFFFE - b->el[2];  /* 26-bit */
  r->el[3] = a->el[3] + 0x3FFFFFE - b->el[3];  /* 25-bit */
  r->el[4] = a->el[4] + 0x7FFFFFE - b->el[4];  /* 26-bit */
  r->el[5] = a->el[5] + 0x3FFFFFE - b->el[5];  /* 25-bit */
  r->el[6] = a->el[6] + 0x7FFFFFE - b->el[6];  /* 26-bit */
  r->el[7] = a->el[7] + 0x3FFFFFE - b->el[7];  /* 25-bit */
  r->el[8] = a->el[8] + 0x7FFFFFE - b->el[8];  /* 26-bit */
  r->el[9] = a->el[9] + 0x3FFFFFE - b->el[9];  /* 25-bit */
  at_f25519_carry( r );
  return r;
}

/* at_f25519_add_nr computes r = a + b without reduction. */
AT_25519_INLINE at_f25519_t *
at_f25519_add_nr( at_f25519_t *       r,
                  at_f25519_t const * a,
                  at_f25519_t const * b ) {
  for( int i = 0; i < 10; i++ ) {
    r->el[i] = a->el[i] + b->el[i];
  }
  return r;
}

/* at_f25519_sub_nr computes r = a - b without reduction. */
AT_25519_INLINE at_f25519_t *
at_f25519_sub_nr( at_f25519_t *       r,
                  at_f25519_t const * a,
                  at_f25519_t const * b ) {
  r->el[0] = a->el[0] + 0x7FFFFDA - b->el[0];  /* 26-bit, -19 adjust */
  r->el[1] = a->el[1] + 0x3FFFFFE - b->el[1];  /* 25-bit */
  r->el[2] = a->el[2] + 0x7FFFFFE - b->el[2];  /* 26-bit */
  r->el[3] = a->el[3] + 0x3FFFFFE - b->el[3];  /* 25-bit */
  r->el[4] = a->el[4] + 0x7FFFFFE - b->el[4];  /* 26-bit */
  r->el[5] = a->el[5] + 0x3FFFFFE - b->el[5];  /* 25-bit */
  r->el[6] = a->el[6] + 0x7FFFFFE - b->el[6];  /* 26-bit */
  r->el[7] = a->el[7] + 0x3FFFFFE - b->el[7];  /* 25-bit */
  r->el[8] = a->el[8] + 0x7FFFFFE - b->el[8];  /* 26-bit */
  r->el[9] = a->el[9] + 0x3FFFFFE - b->el[9];  /* 25-bit */
  return r;
}

/* at_f25519_neg computes r = -a, and returns r. */
AT_25519_INLINE at_f25519_t *
at_f25519_neg( at_f25519_t *       r,
               at_f25519_t const * a ) {
  r->el[0] = 0x7FFFFDA - a->el[0];  /* 26-bit, -19 adjust */
  r->el[1] = 0x3FFFFFE - a->el[1];  /* 25-bit */
  r->el[2] = 0x7FFFFFE - a->el[2];  /* 26-bit */
  r->el[3] = 0x3FFFFFE - a->el[3];  /* 25-bit */
  r->el[4] = 0x7FFFFFE - a->el[4];  /* 26-bit */
  r->el[5] = 0x3FFFFFE - a->el[5];  /* 25-bit */
  r->el[6] = 0x7FFFFFE - a->el[6];  /* 26-bit */
  r->el[7] = 0x3FFFFFE - a->el[7];  /* 25-bit */
  r->el[8] = 0x7FFFFFE - a->el[8];  /* 26-bit */
  r->el[9] = 0x3FFFFFE - a->el[9];  /* 25-bit */
  return r;
}

/* at_f25519_mul_121666 computes r = a * 121666, and returns r. */
AT_25519_INLINE at_f25519_t *
at_f25519_mul_121666( at_f25519_t *       r,
                      at_f25519_t const * a ) {
  uint64_t c = 0;
  for( int i = 0; i < 10; i++ ) {
    c += a->el[i] * 121666UL;
    r->el[i] = c & ((i & 1) ? AT_F25519_MASK25 : AT_F25519_MASK26);
    c >>= (i & 1) ? 25 : 26;
  }
  r->el[0] += 19 * c;
  at_f25519_carry( r );
  return r;
}

/* at_f25519_frombytes deserializes a 32-byte buffer into a field element. */
AT_25519_INLINE at_f25519_t *
at_f25519_frombytes( at_f25519_t * r,
                     uchar const   buf[ 32 ] ) {
  uint64_t t0 = (uint64_t)buf[ 0] | ((uint64_t)buf[ 1] << 8) |
                ((uint64_t)buf[ 2] << 16) | ((uint64_t)buf[ 3] << 24);
  uint64_t t1 = (uint64_t)buf[ 4] | ((uint64_t)buf[ 5] << 8) |
                ((uint64_t)buf[ 6] << 16) | ((uint64_t)buf[ 7] << 24);
  uint64_t t2 = (uint64_t)buf[ 8] | ((uint64_t)buf[ 9] << 8) |
                ((uint64_t)buf[10] << 16) | ((uint64_t)buf[11] << 24);
  uint64_t t3 = (uint64_t)buf[12] | ((uint64_t)buf[13] << 8) |
                ((uint64_t)buf[14] << 16) | ((uint64_t)buf[15] << 24);
  uint64_t t4 = (uint64_t)buf[16] | ((uint64_t)buf[17] << 8) |
                ((uint64_t)buf[18] << 16) | ((uint64_t)buf[19] << 24);
  uint64_t t5 = (uint64_t)buf[20] | ((uint64_t)buf[21] << 8) |
                ((uint64_t)buf[22] << 16) | ((uint64_t)buf[23] << 24);
  uint64_t t6 = (uint64_t)buf[24] | ((uint64_t)buf[25] << 8) |
                ((uint64_t)buf[26] << 16) | ((uint64_t)buf[27] << 24);
  uint64_t t7 = (uint64_t)buf[28] | ((uint64_t)buf[29] << 8) |
                ((uint64_t)buf[30] << 16) | (((uint64_t)buf[31] & 0x7F) << 24);

  /* Convert from 32-bit limbs to alternating 26/25-bit limbs */
  r->el[0] = t0 & AT_F25519_MASK26;
  r->el[1] = ((t0 >> 26) | (t1 << 6)) & AT_F25519_MASK25;
  r->el[2] = ((t1 >> 19) | (t2 << 13)) & AT_F25519_MASK26;
  r->el[3] = ((t2 >> 13) | (t3 << 19)) & AT_F25519_MASK25;
  r->el[4] = (t3 >> 6) & AT_F25519_MASK26;
  r->el[5] = t4 & AT_F25519_MASK25;
  r->el[6] = ((t4 >> 25) | (t5 << 7)) & AT_F25519_MASK26;
  r->el[7] = ((t5 >> 19) | (t6 << 13)) & AT_F25519_MASK25;
  r->el[8] = ((t6 >> 12) | (t7 << 20)) & AT_F25519_MASK26;
  r->el[9] = (t7 >> 6) & AT_F25519_MASK25;

  return r;
}

/* at_f25519_tobytes serializes a field element into a 32-byte buffer. */
AT_25519_INLINE uchar *
at_f25519_tobytes( uchar               out[ 32 ],
                   at_f25519_t const * a ) {
  /* First, fully reduce the element */
  at_f25519_t t;
  for( int i = 0; i < 10; i++ ) t.el[i] = a->el[i];
  at_f25519_carry( &t );

  /* Additional reduction: if >= p, subtract p */
  uint64_t c = t.el[0] + 19;
  c = (c >> 26) + t.el[1];
  c = (c >> 25) + t.el[2];
  c = (c >> 26) + t.el[3];
  c = (c >> 25) + t.el[4];
  c = (c >> 26) + t.el[5];
  c = (c >> 25) + t.el[6];
  c = (c >> 26) + t.el[7];
  c = (c >> 25) + t.el[8];
  c = (c >> 26) + t.el[9];
  c >>= 25;

  t.el[0] += 19 * c;
  at_f25519_carry( &t );

  /* Pack into bytes. Limb bit positions:
     el[0]: 0-25, el[1]: 26-50, el[2]: 51-76, el[3]: 77-101, el[4]: 102-127,
     el[5]: 128-152, el[6]: 153-178, el[7]: 179-203, el[8]: 204-229, el[9]: 230-254 */

  /* Combine limbs into 64-bit values aligned to byte boundaries.
     Byte positions: 0-7=bits 0-63, 8-15=bits 64-127, 16-23=bits 128-191, 24-31=bits 192-255 */
  uint64_t h0 = t.el[0] | (t.el[1] << 26) | (t.el[2] << 51);  /* bits 0-76 (write 0-63) */
  uint64_t h1 = (t.el[2] >> 13) | (t.el[3] << 13) | (t.el[4] << 38);  /* bits 64-127 */
  uint64_t h2 = t.el[5] | (t.el[6] << 25) | (t.el[7] << 51);  /* bits 128-203 (write 128-191) */
  uint64_t h3 = (t.el[7] >> 13) | (t.el[8] << 12) | (t.el[9] << 38);  /* bits 192-254 */

  out[ 0] = (uchar)(h0);
  out[ 1] = (uchar)(h0 >> 8);
  out[ 2] = (uchar)(h0 >> 16);
  out[ 3] = (uchar)(h0 >> 24);
  out[ 4] = (uchar)(h0 >> 32);
  out[ 5] = (uchar)(h0 >> 40);
  out[ 6] = (uchar)(h0 >> 48);
  out[ 7] = (uchar)(h0 >> 56);
  out[ 8] = (uchar)(h1);
  out[ 9] = (uchar)(h1 >> 8);
  out[10] = (uchar)(h1 >> 16);
  out[11] = (uchar)(h1 >> 24);
  out[12] = (uchar)(h1 >> 32);
  out[13] = (uchar)(h1 >> 40);
  out[14] = (uchar)(h1 >> 48);
  out[15] = (uchar)(h1 >> 56);
  out[16] = (uchar)(h2);
  out[17] = (uchar)(h2 >> 8);
  out[18] = (uchar)(h2 >> 16);
  out[19] = (uchar)(h2 >> 24);
  out[20] = (uchar)(h2 >> 32);
  out[21] = (uchar)(h2 >> 40);
  out[22] = (uchar)(h2 >> 48);
  out[23] = (uchar)(h2 >> 56);
  out[24] = (uchar)(h3);
  out[25] = (uchar)(h3 >> 8);
  out[26] = (uchar)(h3 >> 16);
  out[27] = (uchar)(h3 >> 24);
  out[28] = (uchar)(h3 >> 32);
  out[29] = (uchar)(h3 >> 40);
  out[30] = (uchar)(h3 >> 48);
  out[31] = (uchar)(h3 >> 56);

  return out;
}

/* at_f25519_if sets r = a0 if cond, else r = a1 (constant time). */
AT_25519_INLINE at_f25519_t *
at_f25519_if( at_f25519_t *       r,
              int const           cond,
              at_f25519_t const * a0,
              at_f25519_t const * a1 ) {
  uint64_t mask = (uint64_t)(-(long)!!cond);
  for( int i = 0; i < 10; i++ ) {
    r->el[i] = (a0->el[i] & mask) | (a1->el[i] & ~mask);
  }
  return r;
}

/* at_f25519_swap_if swaps r1, r2 if cond (constant time). */
AT_25519_INLINE void
at_f25519_swap_if( at_f25519_t * restrict r1,
                   at_f25519_t * restrict r2,
                   int const              cond ) {
  uint64_t mask = (uint64_t)(-(long)!!cond);
  for( int i = 0; i < 10; i++ ) {
    uint64_t x = mask & (r1->el[i] ^ r2->el[i]);
    r1->el[i] ^= x;
    r2->el[i] ^= x;
  }
}

/* at_f25519_set copies r = a, and returns r. */
AT_25519_INLINE at_f25519_t *
at_f25519_set( at_f25519_t *       r,
               at_f25519_t const * a ) {
  for( int i = 0; i < 10; i++ ) {
    r->el[i] = a->el[i];
  }
  return r;
}

/* at_f25519_canonicalize fully reduces r to canonical form [0, p).
   This is needed after operations that may produce non-canonical outputs
   (values in [p, 2p) instead of [0, p)). Uses the same reduction as tobytes. */
AT_25519_INLINE at_f25519_t *
at_f25519_canonicalize( at_f25519_t * r ) {
  at_f25519_carry( r );

  /* If >= p, subtract p by adding 19 and propagating carries.
     We detect this by checking if adding 19 causes overflow through all limbs. */
  uint64_t c = r->el[0] + 19;
  c = (c >> 26) + r->el[1];
  c = (c >> 25) + r->el[2];
  c = (c >> 26) + r->el[3];
  c = (c >> 25) + r->el[4];
  c = (c >> 26) + r->el[5];
  c = (c >> 25) + r->el[6];
  c = (c >> 26) + r->el[7];
  c = (c >> 25) + r->el[8];
  c = (c >> 26) + r->el[9];
  c >>= 25;

  /* If c == 1, the value was >= p, so we add 19 and reduce.
     Use a special carry chain that doesn't wrap around from limb 9 to limb 0,
     since we've already done the modular reduction by adding 19. */
  r->el[0] += 19 * c;

  /* Carry without wrap-around */
  c = r->el[0] >> 26; r->el[0] &= AT_F25519_MASK26; r->el[1] += c;
  c = r->el[1] >> 25; r->el[1] &= AT_F25519_MASK25; r->el[2] += c;
  c = r->el[2] >> 26; r->el[2] &= AT_F25519_MASK26; r->el[3] += c;
  c = r->el[3] >> 25; r->el[3] &= AT_F25519_MASK25; r->el[4] += c;
  c = r->el[4] >> 26; r->el[4] &= AT_F25519_MASK26; r->el[5] += c;
  c = r->el[5] >> 25; r->el[5] &= AT_F25519_MASK25; r->el[6] += c;
  c = r->el[6] >> 26; r->el[6] &= AT_F25519_MASK26; r->el[7] += c;
  c = r->el[7] >> 25; r->el[7] &= AT_F25519_MASK25; r->el[8] += c;
  c = r->el[8] >> 26; r->el[8] &= AT_F25519_MASK26; r->el[9] += c;
  /* Don't wrap from limb 9 - the value should now be < p */
  r->el[9] &= AT_F25519_MASK25;

  return r;
}

/* at_f25519_is_zero returns 1 if a == 0, 0 otherwise. */
AT_25519_INLINE int
at_f25519_is_zero( at_f25519_t const * a ) {
  /* Use the same full reduction as tobytes */
  at_f25519_t t;
  for( int i = 0; i < 10; i++ ) t.el[i] = a->el[i];
  at_f25519_carry( &t );

  /* Additional reduction: if >= p, subtract p */
  uint64_t c = t.el[0] + 19;
  c = (c >> 26) + t.el[1];
  c = (c >> 25) + t.el[2];
  c = (c >> 26) + t.el[3];
  c = (c >> 25) + t.el[4];
  c = (c >> 26) + t.el[5];
  c = (c >> 25) + t.el[6];
  c = (c >> 26) + t.el[7];
  c = (c >> 25) + t.el[8];
  c = (c >> 26) + t.el[9];
  c >>= 25;

  /* If c == 1, the value was >= p, so we add 19 and reduce.
     Use carry chain without wrap-around. */
  t.el[0] += 19 * c;
  c = t.el[0] >> 26; t.el[0] &= AT_F25519_MASK26; t.el[1] += c;
  c = t.el[1] >> 25; t.el[1] &= AT_F25519_MASK25; t.el[2] += c;
  c = t.el[2] >> 26; t.el[2] &= AT_F25519_MASK26; t.el[3] += c;
  c = t.el[3] >> 25; t.el[3] &= AT_F25519_MASK25; t.el[4] += c;
  c = t.el[4] >> 26; t.el[4] &= AT_F25519_MASK26; t.el[5] += c;
  c = t.el[5] >> 25; t.el[5] &= AT_F25519_MASK25; t.el[6] += c;
  c = t.el[6] >> 26; t.el[6] &= AT_F25519_MASK26; t.el[7] += c;
  c = t.el[7] >> 25; t.el[7] &= AT_F25519_MASK25; t.el[8] += c;
  c = t.el[8] >> 26; t.el[8] &= AT_F25519_MASK26; t.el[9] += c;
  t.el[9] &= AT_F25519_MASK25;  /* Don't wrap - value should now be < p */

  /* Now check if all limbs are zero */
  uint64_t d = t.el[0] | t.el[1] | t.el[2] | t.el[3] | t.el[4] |
               t.el[5] | t.el[6] | t.el[7] | t.el[8] | t.el[9];
  return d == 0;
}

/* at_f25519_eq returns 1 if a == b, 0 otherwise. */
AT_25519_INLINE int
at_f25519_eq( at_f25519_t const * a,
              at_f25519_t const * b ) {
  at_f25519_t r[1];
  at_f25519_sub( r, a, b );
  return at_f25519_is_zero( r );
}

/* ========================================================================
   Vectorized Operations (4-way parallel)

   These functions use at_r2526x10_t to perform 4 field operations in parallel
   using AVX2 SIMD instructions. The workflow is:
   1. Zip 4 scalar elements into SIMD form
   2. Perform SIMD operation
   3. Unzip result back to 4 scalar elements
   ======================================================================== */

/* at_f25519_mul4 computes 4 multiplications in parallel using SIMD. */
AT_25519_INLINE void
at_f25519_mul4( at_f25519_t * r1, at_f25519_t const * a1, at_f25519_t const * b1,
                at_f25519_t * r2, at_f25519_t const * a2, at_f25519_t const * b2,
                at_f25519_t * r3, at_f25519_t const * a3, at_f25519_t const * b3,
                at_f25519_t * r4, at_f25519_t const * a4, at_f25519_t const * b4 ) {
  /* Zip 4 'a' operands and 4 'b' operands into SIMD form */
  at_r2526x10_t a_simd, b_simd, c_simd;
  at_r2526x10_zip( &a_simd, a1, a2, a3, a4 );
  at_r2526x10_zip( &b_simd, b1, b2, b3, b4 );

  /* Perform 4-way parallel multiplication */
  at_r2526x10_intmul( &c_simd, &a_simd, &b_simd );
  c_simd = at_r2526x10_compress( &c_simd );

  /* Unzip results back to scalar form */
  at_r2526x10_unzip( r1, r2, r3, r4, &c_simd );
}

AT_25519_INLINE void
at_f25519_mul3( at_f25519_t * r1, at_f25519_t const * a1, at_f25519_t const * b1,
                at_f25519_t * r2, at_f25519_t const * a2, at_f25519_t const * b2,
                at_f25519_t * r3, at_f25519_t const * a3, at_f25519_t const * b3 ) {
  /* Use 4-way SIMD with a dummy 4th element */
  at_r2526x10_t a_simd, b_simd, c_simd;
  at_r2526x10_zip( &a_simd, a1, a2, a3, a1 );
  at_r2526x10_zip( &b_simd, b1, b2, b3, b1 );

  at_r2526x10_intmul( &c_simd, &a_simd, &b_simd );
  c_simd = at_r2526x10_compress( &c_simd );

  at_f25519_t dummy;
  at_r2526x10_unzip( r1, r2, r3, &dummy, &c_simd );
}

AT_25519_INLINE void
at_f25519_mul2( at_f25519_t * r1, at_f25519_t const * a1, at_f25519_t const * b1,
                at_f25519_t * r2, at_f25519_t const * a2, at_f25519_t const * b2 ) {
  /* Use 4-way SIMD with dummy 3rd/4th elements */
  at_r2526x10_t a_simd, b_simd, c_simd;
  at_r2526x10_zip( &a_simd, a1, a2, a1, a2 );
  at_r2526x10_zip( &b_simd, b1, b2, b1, b2 );

  at_r2526x10_intmul( &c_simd, &a_simd, &b_simd );
  c_simd = at_r2526x10_compress( &c_simd );

  at_f25519_t d1, d2;
  at_r2526x10_unzip( r1, r2, &d1, &d2, &c_simd );
}

/* at_f25519_sqr4 computes 4 squarings in parallel using SIMD. */
AT_25519_INLINE void
at_f25519_sqr4( at_f25519_t * r1, at_f25519_t const * a1,
                at_f25519_t * r2, at_f25519_t const * a2,
                at_f25519_t * r3, at_f25519_t const * a3,
                at_f25519_t * r4, at_f25519_t const * a4 ) {
  at_r2526x10_t a_simd, c_simd;
  at_r2526x10_zip( &a_simd, a1, a2, a3, a4 );

  at_r2526x10_intsqr( &c_simd, &a_simd );
  c_simd = at_r2526x10_compress( &c_simd );

  at_r2526x10_unzip( r1, r2, r3, r4, &c_simd );
}

AT_25519_INLINE void
at_f25519_sqr3( at_f25519_t * r1, at_f25519_t const * a1,
                at_f25519_t * r2, at_f25519_t const * a2,
                at_f25519_t * r3, at_f25519_t const * a3 ) {
  at_r2526x10_t a_simd, c_simd;
  at_r2526x10_zip( &a_simd, a1, a2, a3, a1 );

  at_r2526x10_intsqr( &c_simd, &a_simd );
  c_simd = at_r2526x10_compress( &c_simd );

  at_f25519_t dummy;
  at_r2526x10_unzip( r1, r2, r3, &dummy, &c_simd );
}

AT_25519_INLINE void
at_f25519_sqr2( at_f25519_t * r1, at_f25519_t const * a1,
                at_f25519_t * r2, at_f25519_t const * a2 ) {
  at_r2526x10_t a_simd, c_simd;
  at_r2526x10_zip( &a_simd, a1, a2, a1, a2 );

  at_r2526x10_intsqr( &c_simd, &a_simd );
  c_simd = at_r2526x10_compress( &c_simd );

  at_f25519_t d1, d2;
  at_r2526x10_unzip( r1, r2, &d1, &d2, &c_simd );
}

/* ========================================================================
   Modular Inversion and Square Root
   ======================================================================== */

/* at_f25519_pow22523 computes r = a^(2^252-3), used for square root. */
AT_25519_INLINE at_f25519_t *
at_f25519_pow22523( at_f25519_t *       r,
                    at_f25519_t const * a ) {
  at_f25519_t t0[1], t1[1], t2[1];

  /* 2^1 */
  at_f25519_sqr( t0, a );
  /* 2^2 */
  at_f25519_sqr( t1, t0 );
  at_f25519_sqr( t1, t1 );
  /* 2^2 * a */
  at_f25519_mul( t1, t1, a );
  /* 2^3 - 1 */
  at_f25519_mul( t0, t0, t1 );
  /* 2^3 */
  at_f25519_sqr( t0, t0 );
  /* 2^5 - 2^1 + 1 = 2^5 - 1 */
  at_f25519_mul( t0, t0, t1 );
  /* 2^10 - 2^5 */
  at_f25519_sqr( t1, t0 );
  for( int i = 0; i < 4; i++ ) at_f25519_sqr( t1, t1 );
  /* 2^10 - 1 */
  at_f25519_mul( t0, t1, t0 );
  /* 2^20 - 2^10 */
  at_f25519_sqr( t1, t0 );
  for( int i = 0; i < 9; i++ ) at_f25519_sqr( t1, t1 );
  /* 2^20 - 1 */
  at_f25519_mul( t1, t1, t0 );
  /* 2^40 - 2^20 */
  at_f25519_sqr( t2, t1 );
  for( int i = 0; i < 19; i++ ) at_f25519_sqr( t2, t2 );
  /* 2^40 - 1 */
  at_f25519_mul( t1, t2, t1 );
  /* 2^50 - 2^10 */
  for( int i = 0; i < 10; i++ ) at_f25519_sqr( t1, t1 );
  /* 2^50 - 1 */
  at_f25519_mul( t0, t1, t0 );
  /* 2^100 - 2^50 */
  at_f25519_sqr( t1, t0 );
  for( int i = 0; i < 49; i++ ) at_f25519_sqr( t1, t1 );
  /* 2^100 - 1 */
  at_f25519_mul( t1, t1, t0 );
  /* 2^200 - 2^100 */
  at_f25519_sqr( t2, t1 );
  for( int i = 0; i < 99; i++ ) at_f25519_sqr( t2, t2 );
  /* 2^200 - 1 */
  at_f25519_mul( t1, t2, t1 );
  /* 2^250 - 2^50 */
  for( int i = 0; i < 50; i++ ) at_f25519_sqr( t1, t1 );
  /* 2^250 - 1 */
  at_f25519_mul( t0, t1, t0 );
  /* 2^252 - 4 */
  at_f25519_sqr( t0, t0 );
  at_f25519_sqr( t0, t0 );
  /* 2^252 - 3 */
  at_f25519_mul( r, t0, a );

  return r;
}

/* at_f25519_inv computes r = 1/a mod p using Fermat's little theorem.
   a^(-1) = a^(p-2) mod p where p = 2^255-19.
   Note: Returns undefined result if a == 0. */
AT_25519_INLINE at_f25519_t *
at_f25519_inv( at_f25519_t *       r,
               at_f25519_t const * a ) {
  at_f25519_t t[1];
  /* a^(2^252-3) */
  at_f25519_pow22523( t, a );
  /* a^(2^252-3) * a = a^(2^252-2) */
  at_f25519_mul( t, t, a );
  /* (a^(2^252-2))^4 = a^(2^254-8) */
  at_f25519_sqr( t, t );
  at_f25519_sqr( t, t );
  /* a^(2^254-8) * a = a^(2^254-7) */
  at_f25519_mul( t, t, a );
  /* (a^(2^254-7))^2 = a^(2^255-14) */
  at_f25519_sqr( t, t );
  /* a^(2^255-14) * a = a^(2^255-13) ... this continues */
  /* Actually p-2 = 2^255-21, using proper exponentiation */
  /* Let's use correct chain: */

  /* Reset and use proper chain for p-2 = 2^255 - 21 */
  at_f25519_t t0[1], t1[1], t2[1];

  at_f25519_sqr( t0, a );       /* 2 */
  at_f25519_sqr( t1, t0 );      /* 4 */
  at_f25519_sqr( t1, t1 );      /* 8 */
  at_f25519_mul( t1, t1, a );   /* 9 */
  at_f25519_mul( t0, t0, t1 );  /* 11 */
  at_f25519_sqr( t1, t0 );      /* 22 */
  at_f25519_mul( t1, t1, t1 );  /* This is wrong, let me simplify */

  /* Use pow22523 as base: a^(2^252-3) then multiply by a^5 to get a^(2^252+2)
     Actually simpler: p-2 = 2^255 - 21
     Let's compute via a^(p-2) = (a^(2^5-1))^(2^250) * a^(2^255-32+11)
     This is getting complex. Use the standard addition chain. */

  /* Standard Fermat inversion for curve25519 */
  at_f25519_sqr( t0, a );        /* a^2 */
  at_f25519_sqr( t1, t0 );       /* a^4 */
  at_f25519_sqr( t1, t1 );       /* a^8 */
  at_f25519_mul( t1, t1, a );    /* a^9 */
  at_f25519_mul( t0, t0, t1 );   /* a^11 */
  at_f25519_sqr( t2, t0 );       /* a^22 */
  at_f25519_mul( t1, t1, t2 );   /* a^31 = a^(2^5-1) */

  at_f25519_sqr( t2, t1 );
  for( int i = 0; i < 4; i++ ) at_f25519_sqr( t2, t2 );
  at_f25519_mul( t1, t2, t1 );   /* a^(2^10-1) */

  at_f25519_sqr( t2, t1 );
  for( int i = 0; i < 9; i++ ) at_f25519_sqr( t2, t2 );
  at_f25519_mul( t2, t2, t1 );   /* a^(2^20-1) */

  at_f25519_sqr( t1, t2 );
  for( int i = 0; i < 19; i++ ) at_f25519_sqr( t1, t1 );
  at_f25519_mul( t2, t1, t2 );   /* a^(2^40-1) */

  at_f25519_sqr( t1, t2 );
  for( int i = 0; i < 9; i++ ) at_f25519_sqr( t1, t1 );
  /* ... continue building up to 2^255-21 */

  /* Shortcut: reuse pow22523 and adjust */
  at_f25519_pow22523( t, a );
  /* t = a^(2^252-3) */
  /* Need a^(2^255-21) = a^(8*(2^252-3) + 3) = (a^(2^252-3))^8 * a^3 */
  at_f25519_sqr( t, t );
  at_f25519_sqr( t, t );
  at_f25519_sqr( t, t );         /* t = a^(2^255-24) */
  at_f25519_mul( t, t, a );      /* t = a^(2^255-23) */
  at_f25519_mul( t, t, a );      /* t = a^(2^255-22) */
  at_f25519_mul( r, t, a );      /* r = a^(2^255-21) = a^(p-2) */

  return r;
}

/* at_f25519_sqrt_ratio computes r = sqrt(u/v) if it exists.
   Returns 0 on success, 1 if no square root exists. */
AT_25519_INLINE int
at_f25519_sqrt_ratio( at_f25519_t *       r,
                      at_f25519_t const * u,
                      at_f25519_t const * v ) {
  at_f25519_t v3[1], v7[1], uv3[1], uv7[1], t[1];

  /* v^3 */
  at_f25519_sqr( v3, v );
  at_f25519_mul( v3, v3, v );

  /* v^7 */
  at_f25519_sqr( v7, v3 );
  at_f25519_mul( v7, v7, v );

  /* (u * v^3) */
  at_f25519_mul( uv3, u, v3 );

  /* (u * v^7) */
  at_f25519_mul( uv7, u, v7 );

  /* (u * v^7)^((p-5)/8) = (u * v^7)^(2^252-3) */
  at_f25519_pow22523( t, uv7 );

  /* r = (u * v^3) * (u * v^7)^((p-5)/8) */
  at_f25519_mul( r, uv3, t );

  /* Check if r^2 * v == u */
  at_f25519_sqr( t, r );
  at_f25519_mul( t, t, v );
  at_f25519_sub( t, t, u );

  if( at_f25519_is_zero( t ) ) return 0;

  /* Try r * sqrt(-1) */
  at_f25519_mul( r, r, at_f25519_sqrtm1 );

  at_f25519_sqr( t, r );
  at_f25519_mul( t, t, v );
  at_f25519_sub( t, t, u );

  if( at_f25519_is_zero( t ) ) return 0;

  return 1; /* No square root */
}

/* at_f25519_sgn returns the sign (least significant bit) of a. */
AT_25519_INLINE int
at_f25519_sgn( at_f25519_t const * a ) {
  uchar buf[32];
  at_f25519_tobytes( buf, a );
  return buf[0] & 1;
}

AT_PROTOTYPES_END

#endif /* AT_HAS_AVX && !AT_HAS_AVX512_IFMA */

#endif /* HEADER_at_src_crypto_ed25519_avx2_at_f25519_h */
