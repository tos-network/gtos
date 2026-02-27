/* Avatar SHA3 implementation
   - SHA3-256: TOS transaction hashing
   - SHA3-512: TOS signature hashing (Schnorr-variant) */

#include "at_sha3.h"
#include "at/infra/at_util.h"
#include "at_sha3_private.h"

#ifndef AT_LOG_WARNING
#define AT_LOG_WARNING(args) ((void)0)
#endif

/**********************************************************************/
/* SHA3-256 Implementation                                             */
/**********************************************************************/

ulong
at_sha3_256_align( void ) {
  return AT_SHA3_256_ALIGN;
}

ulong
at_sha3_256_footprint( void ) {
  return AT_SHA3_256_FOOTPRINT;
}

void *
at_sha3_256_new( void * shmem ) {
  at_sha3_256_t * sha = (at_sha3_256_t *)shmem;

  if( AT_UNLIKELY( !shmem ) ) {
    AT_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)shmem, at_sha3_256_align() ) ) ) {
    AT_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = at_sha3_256_footprint();

  at_memset( sha, 0, footprint );

  AT_COMPILER_MFENCE();
  AT_VOLATILE( sha->magic ) = AT_SHA3_256_MAGIC;
  AT_COMPILER_MFENCE();

  return (void *)sha;
}

at_sha3_256_t *
at_sha3_256_join( void * shsha ) {

  if( AT_UNLIKELY( !shsha ) ) {
    AT_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)shsha, at_sha3_256_align() ) ) ) {
    AT_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  at_sha3_256_t * sha = (at_sha3_256_t *)shsha;

  if( AT_UNLIKELY( sha->magic!=AT_SHA3_256_MAGIC ) ) {
    AT_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return sha;
}

void *
at_sha3_256_leave( at_sha3_256_t * sha ) {

  if( AT_UNLIKELY( !sha ) ) {
    AT_LOG_WARNING(( "NULL sha" ));
    return NULL;
  }

  return (void *)sha;
}

void *
at_sha3_256_delete( void * shsha ) {

  if( AT_UNLIKELY( !shsha ) ) {
    AT_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)shsha, at_sha3_256_align() ) ) ) {
    AT_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  at_sha3_256_t * sha = (at_sha3_256_t *)shsha;

  if( AT_UNLIKELY( sha->magic!=AT_SHA3_256_MAGIC ) ) {
    AT_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  AT_COMPILER_MFENCE();
  AT_VOLATILE( sha->magic ) = 0UL;
  AT_COMPILER_MFENCE();

  return (void *)sha;
}

at_sha3_256_t *
at_sha3_256_init( at_sha3_256_t * sha ) {
  at_memset( sha->state, 0, sizeof( sha->state ) );
  sha->padding_start = 0;
  return sha;
}

at_sha3_256_t *
at_sha3_256_append( at_sha3_256_t * sha,
                    void const *    _data,
                    ulong           sz ) {

  /* If no data to append, we are done */
  if( AT_UNLIKELY( !sz ) ) return sha;

  /* Unpack inputs */
  ulong * state         = sha->state;
  uchar * state_bytes   = (uchar*) sha->state;
  ulong   padding_start = sha->padding_start;

  uchar const * data = (uchar const *)_data;

  ulong state_idx = padding_start;
  for( ulong i = 0; i < sz; i++ ) {
    state_bytes[state_idx] ^= data[i];
    state_idx++;
    if( state_idx >= AT_SHA3_256_RATE ) {
      at_sha3_keccak_core(state);
      state_idx = 0;
    }
  }

  sha->padding_start = state_idx;

  return sha;
}

void *
at_sha3_256_fini( at_sha3_256_t * sha,
                  void *          hash ) {

  /* Unpack inputs */
  ulong * state         = sha->state;
  uchar * state_bytes   = (uchar*) sha->state;
  ulong   padding_start = sha->padding_start;

  /* SHA3 padding: 0x06 ... 0x80 */
  state_bytes[padding_start] ^= (uchar)0x06;
  state_bytes[AT_SHA3_256_RATE-1] ^= (uchar)0x80;
  at_sha3_keccak_core(state);

  /* Copy the result into hash (32 bytes for SHA3-256) */
  at_memcpy(hash, state, AT_SHA3_256_OUT_SZ);
  return hash;
}

void *
at_sha3_256_hash( void const * _data,
                  ulong        sz,
                  void *       _hash ) {
  at_sha3_256_t sha[1];
  at_sha3_256_init( sha );
  at_sha3_256_append( sha, _data, sz );
  at_sha3_256_fini( sha, _hash );
  return _hash;
}

/**********************************************************************/
/* SHA3-512 Implementation                                             */
/**********************************************************************/

ulong
at_sha3_512_align( void ) {
  return AT_SHA3_512_ALIGN;
}

ulong
at_sha3_512_footprint( void ) {
  return AT_SHA3_512_FOOTPRINT;
}

void *
at_sha3_512_new( void * shmem ) {
  at_sha3_512_t * sha = (at_sha3_512_t *)shmem;

  if( AT_UNLIKELY( !shmem ) ) {
    AT_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)shmem, at_sha3_512_align() ) ) ) {
    AT_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = at_sha3_512_footprint();

  at_memset( sha, 0, footprint );

  AT_COMPILER_MFENCE();
  AT_VOLATILE( sha->magic ) = AT_SHA3_512_MAGIC;
  AT_COMPILER_MFENCE();

  return (void *)sha;
}

at_sha3_512_t *
at_sha3_512_join( void * shsha ) {

  if( AT_UNLIKELY( !shsha ) ) {
    AT_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)shsha, at_sha3_512_align() ) ) ) {
    AT_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  at_sha3_512_t * sha = (at_sha3_512_t *)shsha;

  if( AT_UNLIKELY( sha->magic!=AT_SHA3_512_MAGIC ) ) {
    AT_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return sha;
}

void *
at_sha3_512_leave( at_sha3_512_t * sha ) {

  if( AT_UNLIKELY( !sha ) ) {
    AT_LOG_WARNING(( "NULL sha" ));
    return NULL;
  }

  return (void *)sha;
}

void *
at_sha3_512_delete( void * shsha ) {

  if( AT_UNLIKELY( !shsha ) ) {
    AT_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)shsha, at_sha3_512_align() ) ) ) {
    AT_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  at_sha3_512_t * sha = (at_sha3_512_t *)shsha;

  if( AT_UNLIKELY( sha->magic!=AT_SHA3_512_MAGIC ) ) {
    AT_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  AT_COMPILER_MFENCE();
  AT_VOLATILE( sha->magic ) = 0UL;
  AT_COMPILER_MFENCE();

  return (void *)sha;
}

at_sha3_512_t *
at_sha3_512_init( at_sha3_512_t * sha ) {
  at_memset( sha->state, 0, sizeof( sha->state ) );
  sha->padding_start = 0;
  return sha;
}

at_sha3_512_t *
at_sha3_512_append( at_sha3_512_t * sha,
                    void const *    _data,
                    ulong           sz ) {

  /* If no data to append, we are done */
  if( AT_UNLIKELY( !sz ) ) return sha;

  /* Unpack inputs */
  ulong * state         = sha->state;
  uchar * state_bytes   = (uchar*) sha->state;
  ulong   padding_start = sha->padding_start;

  uchar const * data = (uchar const *)_data;

  ulong state_idx = padding_start;
  for( ulong i = 0; i < sz; i++ ) {
    state_bytes[state_idx] ^= data[i];
    state_idx++;
    if( state_idx >= AT_SHA3_512_RATE ) {
      at_sha3_keccak_core(state);
      state_idx = 0;
    }
  }

  sha->padding_start = state_idx;

  return sha;
}

void *
at_sha3_512_fini( at_sha3_512_t * sha,
                  void *          hash ) {

  /* Unpack inputs */
  ulong * state         = sha->state;
  uchar * state_bytes   = (uchar*) sha->state;
  ulong   padding_start = sha->padding_start;

  /* SHA3 padding: 0x06 ... 0x80
     Note: Keccak uses 0x01, but NIST SHA3 uses 0x06 */
  state_bytes[padding_start] ^= (uchar)0x06;
  state_bytes[AT_SHA3_512_RATE-1] ^= (uchar)0x80;
  at_sha3_keccak_core(state);

  /* Copy the result into hash (64 bytes for SHA3-512) */
  at_memcpy(hash, state, AT_SHA3_512_OUT_SZ);
  return hash;
}

void *
at_sha3_512_hash( void const * _data,
                  ulong        sz,
                  void *       _hash ) {
  at_sha3_512_t sha[1];
  at_sha3_512_init( sha );
  at_sha3_512_append( sha, _data, sz );
  at_sha3_512_fini( sha, _hash );
  return _hash;
}
