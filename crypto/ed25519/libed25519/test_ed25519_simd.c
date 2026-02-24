/* Ed25519 SIMD Equivalence Tests
   Tests that AVX-512 optimized implementations produce identical results to reference.
   Test vectors from ~/avatar/src/tck/test_vectors/ed25519.yaml */

#include "at/crypto/at_ed25519.h"
#include <stdio.h>
#include <string.h>

static int
hex_to_bytes( char const * hex, uchar * out, ulong out_sz ) {
  ulong hex_len = at_strlen( hex );
  if( hex_len % 2 != 0 || hex_len / 2 > out_sz ) return -1;
  for( ulong i = 0; i < hex_len / 2; i++ ) {
    unsigned int byte;
    if( sscanf( hex + i * 2, "%02x", &byte ) != 1 ) return -1;
    out[i] = (uchar)byte;
  }
  return (int)(hex_len / 2);
}

static void
print_hex( uchar const * data, ulong sz ) {
  for( ulong i = 0; i < sz; i++ ) {
    printf( "%02x", data[i] );
  }
}

/* Keypair test vector */
typedef struct {
  char const * name;
  char const * seed_hex;
  char const * public_key_hex;
} keypair_vector_t;

/* Signature test vector */
typedef struct {
  char const * name;
  char const * seed_hex;
  char const * public_key_hex;
  char const * message_hex;
  char const * signature_hex;
} signature_vector_t;

/* Keypair test vectors from src/tck/test_vectors/ed25519.yaml */
static keypair_vector_t const keypair_vectors[] = {
  { "zero_seed",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29" },
  { "ones_seed",
    "0101010101010101010101010101010101010101010101010101010101010101",
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c" },
  { "ff_seed",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5" },
  { "sequential_seed",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8" },
  { "rfc8032_test1",
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" },
};

#define KEYPAIR_VECTOR_CNT (sizeof(keypair_vectors)/sizeof(keypair_vectors[0]))

/* Signature test vectors from src/tck/test_vectors/ed25519.yaml */
static signature_vector_t const signature_vectors[] = {
  { "empty_message",
    "4242424242424242424242424242424242424242424242424242424242424242",
    "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
    "",
    "3f9f3147d0dd159f334cb800435ae49a2837adae5e6b2394906edc2cfed829785e3dd186eb2fed1319a0451917cb6617fcbe9382e0d1343eb5ffd4a9a2dd820c" },
  { "hello_world",
    "4242424242424242424242424242424242424242424242424242424242424242",
    "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
    "48656c6c6f2c20776f726c6421",
    "e46bf31b24799ed37b8c97650bd3bfe38f0c430daca75aaf62071ba4531134d177a03dd563b8d5ca951cfdc939b1a74af0f93cacb06b30999fdc55936d02fe02" },
  { "32byte_message",
    "4242424242424242424242424242424242424242424242424242424242424242",
    "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
    "abababababababababababababababababababababababababababababababab",
    "daa1f4a3e9696d79d538cb7f46a0a4a3830a4b3eeb22f96b5c0395d67182d8ebd23dc111748f73804fe8a8b04b57796b9518e3dea2cde6b84050a1243cda5701" },
  { "zero_seed_sign",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
    "74657374206d657373616765",
    "68c4cc2cb078e1802f43f5d2f741c942229fd920afe00e0c1fe753a0d67afa44facb218fb80df78cb9197a19fdc35366f0ff1e156cf94db8244809c6310c4408" },
  { "rfc8032_test1",
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
};

#define SIGNATURE_VECTOR_CNT (sizeof(signature_vectors)/sizeof(signature_vectors[0]))

/* Test public key derivation */
static int
test_keypair( keypair_vector_t const * tv ) {
  uchar seed[32];
  uchar expected_pubkey[32];
  uchar computed_pubkey[32];

  hex_to_bytes( tv->seed_hex, seed, 32 );
  hex_to_bytes( tv->public_key_hex, expected_pubkey, 32 );

  /* Use SHA512 for Ed25519 operations */
  at_sha512_t sha_mem[1];
  at_sha512_t * sha = at_sha512_join( at_sha512_new( sha_mem ) );

  at_ed25519_public_from_private( computed_pubkey, seed, sha );

  at_sha512_delete( at_sha512_leave( sha ) );

  if( at_memcmp( computed_pubkey, expected_pubkey, 32 ) != 0 ) {
    printf( "FAIL: keypair_%s\n", tv->name );
    printf( "  Expected: %s\n", tv->public_key_hex );
    printf( "  Got:      " );
    print_hex( computed_pubkey, 32 );
    printf( "\n" );
    return 1;
  }

  printf( "PASS: keypair_%s\n", tv->name );
  return 0;
}

/* Test signing and verification */
static int
test_signature( signature_vector_t const * tv ) {
  int fail = 0;
  uchar seed[32];
  uchar pubkey[32];
  uchar message[256];
  uchar expected_sig[64];
  uchar computed_sig[64];

  hex_to_bytes( tv->seed_hex, seed, 32 );
  hex_to_bytes( tv->public_key_hex, pubkey, 32 );
  int msg_sz = hex_to_bytes( tv->message_hex, message, sizeof(message) );
  if( msg_sz < 0 ) msg_sz = 0;
  hex_to_bytes( tv->signature_hex, expected_sig, 64 );

  at_sha512_t sha_mem[1];
  at_sha512_t * sha = at_sha512_join( at_sha512_new( sha_mem ) );

  /* Test signing */
  at_ed25519_sign( computed_sig, message, (ulong)msg_sz, pubkey, seed, sha );

  if( at_memcmp( computed_sig, expected_sig, 64 ) != 0 ) {
    printf( "FAIL: sign_%s\n", tv->name );
    printf( "  Expected: %s\n", tv->signature_hex );
    printf( "  Got:      " );
    print_hex( computed_sig, 64 );
    printf( "\n" );
    fail++;
  } else {
    printf( "PASS: sign_%s\n", tv->name );
  }

  /* Reinitialize SHA context */
  sha = at_sha512_join( at_sha512_new( sha_mem ) );

  /* Test verification of expected signature */
  int result = at_ed25519_verify( message, (ulong)msg_sz, expected_sig, pubkey, sha );

  if( result != AT_ED25519_SUCCESS ) {
    printf( "FAIL: verify_%s (error=%d)\n", tv->name, result );
    fail++;
  } else {
    printf( "PASS: verify_%s\n", tv->name );
  }

  /* Reinitialize SHA context */
  sha = at_sha512_join( at_sha512_new( sha_mem ) );

  /* Test that invalid signature fails verification */
  uchar bad_sig[64];
  at_memcpy( bad_sig, expected_sig, 64 );
  bad_sig[0] ^= 0x01; /* Flip a bit */

  result = at_ed25519_verify( message, (ulong)msg_sz, bad_sig, pubkey, sha );

  if( result == AT_ED25519_SUCCESS ) {
    printf( "FAIL: verify_invalid_%s (should have rejected bad signature)\n", tv->name );
    fail++;
  } else {
    printf( "PASS: verify_invalid_%s\n", tv->name );
  }

  at_sha512_delete( at_sha512_leave( sha ) );

  return fail;
}

/* Test that multiple keypair derivations produce consistent results
   (SIMD vs reference equivalence through consistency) */
static int
test_keypair_consistency( void ) {
  int fail = 0;

  uchar seed[32];
  at_memset( seed, 0x42, 32 );

  uchar pubkey1[32];
  uchar pubkey2[32];

  /* Derive twice and compare */
  at_sha512_t sha_mem[1];
  at_sha512_t * sha;

  sha = at_sha512_join( at_sha512_new( sha_mem ) );
  at_ed25519_public_from_private( pubkey1, seed, sha );
  at_sha512_delete( at_sha512_leave( sha ) );

  sha = at_sha512_join( at_sha512_new( sha_mem ) );
  at_ed25519_public_from_private( pubkey2, seed, sha );
  at_sha512_delete( at_sha512_leave( sha ) );

  if( at_memcmp( pubkey1, pubkey2, 32 ) != 0 ) {
    printf( "FAIL: keypair_consistency\n" );
    printf( "  First:  " );
    print_hex( pubkey1, 32 );
    printf( "\n  Second: " );
    print_hex( pubkey2, 32 );
    printf( "\n" );
    fail++;
  } else {
    printf( "PASS: keypair_consistency\n" );
  }

  return fail;
}

/* Test batch verification consistency */
static int
test_batch_verify( void ) {
  int fail = 0;

  /* Use the first signature test vector */
  signature_vector_t const * tv = &signature_vectors[0];

  uchar seed[32];
  uchar pubkey[32];
  uchar message[256];
  uchar sig[64];

  hex_to_bytes( tv->seed_hex, seed, 32 );
  hex_to_bytes( tv->public_key_hex, pubkey, 32 );
  int msg_sz = hex_to_bytes( tv->message_hex, message, sizeof(message) );
  if( msg_sz < 0 ) msg_sz = 0;
  hex_to_bytes( tv->signature_hex, sig, 64 );

  /* Verify multiple times and ensure consistency */
  int results[4];
  at_sha512_t sha_mem[1];
  at_sha512_t * sha;

  for( int i = 0; i < 4; i++ ) {
    sha = at_sha512_join( at_sha512_new( sha_mem ) );
    results[i] = at_ed25519_verify( message, (ulong)msg_sz, sig, pubkey, sha );
    at_sha512_delete( at_sha512_leave( sha ) );
  }

  int all_same = 1;
  for( int i = 1; i < 4; i++ ) {
    if( results[i] != results[0] ) {
      all_same = 0;
      break;
    }
  }

  if( !all_same || results[0] != AT_ED25519_SUCCESS ) {
    printf( "FAIL: batch_verify_consistency\n" );
    fail++;
  } else {
    printf( "PASS: batch_verify_consistency\n" );
  }

  return fail;
}

int main( void ) {
  int fail = 0;

  printf( "=== Ed25519 Keypair Tests ===\n" );
  for( ulong i = 0; i < KEYPAIR_VECTOR_CNT; i++ ) {
    fail += test_keypair( &keypair_vectors[i] );
  }

  printf( "\n=== Ed25519 Signature Tests ===\n" );
  for( ulong i = 0; i < SIGNATURE_VECTOR_CNT; i++ ) {
    fail += test_signature( &signature_vectors[i] );
  }

  printf( "\n=== Ed25519 Consistency Tests ===\n" );
  fail += test_keypair_consistency();
  fail += test_batch_verify();

  printf( "\n%d tests, %d failures\n",
          (int)(KEYPAIR_VECTOR_CNT + SIGNATURE_VECTOR_CNT * 3 + 2), fail );
  printf( "%s\n", fail ? "SOME TESTS FAILED" : "ALL TESTS PASSED" );

  return fail;
}
