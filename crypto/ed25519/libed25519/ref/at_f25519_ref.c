#include "at_f25519.h"

/* at_f25519_rng generates a random at_f25519_t element.
   Note: insecure, for tests only. */
at_f25519_t *
at_f25519_rng_unsafe( at_f25519_t * r,
                      at_rng_t *    rng ) {
#if USE_FIAT_32
  r->el[0] = at_rng_uint( rng );
  r->el[1] = at_rng_uint( rng );
  r->el[2] = at_rng_uint( rng );
  r->el[3] = at_rng_uint( rng );
  r->el[4] = at_rng_uint( rng );
  r->el[5] = at_rng_uint( rng );
  r->el[6] = at_rng_uint( rng );
  r->el[7] = at_rng_uint( rng );
  r->el[8] = at_rng_uint( rng );
  r->el[9] = at_rng_uint( rng );
#else
  r->el[0] = at_rng_ulong( rng );
  r->el[1] = at_rng_ulong( rng );
  r->el[2] = at_rng_ulong( rng );
  r->el[3] = at_rng_ulong( rng );
  r->el[4] = at_rng_ulong( rng );
#endif
  fiat_25519_carry( r->el, r->el );
  return r;
}