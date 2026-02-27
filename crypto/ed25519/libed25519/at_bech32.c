/* at_bech32.c - Bech32 encoding/decoding for TOS addresses

   Implements BIP-173 Bech32 encoding with TOS-specific prefixes:
   - Mainnet: "tos"
   - Testnet: "tst"

   Reference: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki */

#include "at/crypto/at_bech32.h"
#include <string.h>
#include <ctype.h>

/* Bech32 character set */
static char const charset[] = AT_BECH32_CHARSET;

/* Generator polynomial coefficients for Bech32 checksum */
static uint const generator[ 5 ] = {
  0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
};

/* Reverse lookup table: ASCII -> charset index, 255 = invalid */
static uchar const charset_rev[ 128 ] = {
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  15,  255, 10,  17,  21,  20,  26,  30,  7,   5,   255, 255, 255, 255, 255, 255,
  255, 29,  255, 24,  13,  25,  9,   8,   23,  255, 18,  22,  31,  27,  19,  255,
  1,   0,   3,   16,  11,  28,  12,  14,  6,   4,   2,   255, 255, 255, 255, 255,
  255, 29,  255, 24,  13,  25,  9,   8,   23,  255, 18,  22,  31,  27,  19,  255,
  1,   0,   3,   16,  11,  28,  12,  14,  6,   4,   2,   255, 255, 255, 255, 255
};

/* Compute the Bech32 checksum polymod */
static uint
at_bech32_polymod( uchar const * values, ulong len ) {
  uint chk = 1;
  for( ulong i = 0; i < len; i++ ) {
    uint top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ values[ i ];
    for( int j = 0; j < 5; j++ ) {
      if( (top >> j) & 1 ) {
        chk ^= generator[ j ];
      }
    }
  }
  return chk;
}

/* Expand HRP for checksum calculation:
   [hrp[0]>>5, hrp[1]>>5, ..., 0, hrp[0]&31, hrp[1]&31, ...] */
static ulong
at_bech32_hrp_expand( uchar * out, char const * hrp, ulong hrp_len ) {
  for( ulong i = 0; i < hrp_len; i++ ) {
    out[ i ] = (uchar)(hrp[ i ] >> 5);
  }
  out[ hrp_len ] = 0;
  for( ulong i = 0; i < hrp_len; i++ ) {
    out[ hrp_len + 1 + i ] = (uchar)(hrp[ i ] & 31);
  }
  return hrp_len * 2 + 1;
}

/* Create 6-byte checksum for hrp and data */
static void
at_bech32_create_checksum( uchar * checksum, char const * hrp, uchar const * data, ulong data_len ) {
  ulong hrp_len = at_strlen( hrp );

  /* Allocate buffer for hrp_expand + data + 6 zeros */
  ulong values_len = hrp_len * 2 + 1 + data_len + 6;
  uchar values[ 256 ]; /* Should be enough for any reasonable address */

  ulong pos = at_bech32_hrp_expand( values, hrp, hrp_len );
  at_memcpy( values + pos, data, data_len );
  pos += data_len;
  at_memset( values + pos, 0, 6 );

  uint polymod = at_bech32_polymod( values, values_len ) ^ 1;

  for( int i = 0; i < 6; i++ ) {
    checksum[ i ] = (uchar)((polymod >> (5 * (5 - i))) & 31);
  }
}

/* Verify checksum */
static int
at_bech32_verify_checksum_internal( char const * hrp, uchar const * data, ulong data_len ) {
  ulong hrp_len = at_strlen( hrp );

  ulong values_len = hrp_len * 2 + 1 + data_len;
  uchar values[ 256 ];

  ulong pos = at_bech32_hrp_expand( values, hrp, hrp_len );
  at_memcpy( values + pos, data, data_len );

  return at_bech32_polymod( values, values_len ) == 1;
}

int
at_bech32_convert_bits( uchar *       out,
                        ulong *       out_sz,
                        int           to_bits,
                        uchar const * in,
                        ulong         in_sz,
                        int           from_bits,
                        int           pad ) {
  uint acc = 0;
  int bits = 0;
  ulong out_idx = 0;
  uint max_value = (1u << to_bits) - 1;

  for( ulong i = 0; i < in_sz; i++ ) {
    uint value = in[ i ];

    /* Check input value is in range */
    if( value >> from_bits ) {
      return AT_BECH32_ERR_DATA_INVALID;
    }

    acc = (acc << from_bits) | value;
    bits += from_bits;

    while( bits >= to_bits ) {
      bits -= to_bits;
      if( out_idx >= *out_sz ) {
        return AT_BECH32_ERR_BUFFER_TOO_SMALL;
      }
      out[ out_idx++ ] = (uchar)((acc >> bits) & max_value);
    }
  }

  if( pad ) {
    if( bits > 0 ) {
      if( out_idx >= *out_sz ) {
        return AT_BECH32_ERR_BUFFER_TOO_SMALL;
      }
      out[ out_idx++ ] = (uchar)((acc << (to_bits - bits)) & max_value);
    }
  } else {
    if( bits >= from_bits ) {
      return AT_BECH32_ERR_PADDING_INVALID;
    }
    if( ((acc << (to_bits - bits)) & max_value) != 0 ) {
      return AT_BECH32_ERR_PADDING_INVALID;
    }
  }

  *out_sz = out_idx;
  return AT_BECH32_OK;
}

int
at_bech32_encode( char *        out,
                  ulong         out_sz,
                  char const *  hrp,
                  uchar const * data,
                  ulong         data_sz ) {
  /* Validate HRP */
  ulong hrp_len = at_strlen( hrp );
  if( hrp_len == 0 ) {
    return AT_BECH32_ERR_HRP_EMPTY;
  }

  int has_upper = 0, has_lower = 0;
  for( ulong i = 0; i < hrp_len; i++ ) {
    char c = hrp[ i ];
    if( c < 33 || c > 126 ) {
      return AT_BECH32_ERR_HRP_INVALID_CHAR;
    }
    if( c >= 'A' && c <= 'Z' ) has_upper = 1;
    if( c >= 'a' && c <= 'z' ) has_lower = 1;
  }
  if( has_upper && has_lower ) {
    return AT_BECH32_ERR_HRP_MIX_CASE;
  }

  /* Check output buffer size:
     hrp_len + 1 (separator) + data_sz + 6 (checksum) + 1 (null) */
  ulong needed = hrp_len + 1 + data_sz + AT_BECH32_CHECKSUM_LEN + 1;
  if( out_sz < needed ) {
    return AT_BECH32_ERR_BUFFER_TOO_SMALL;
  }

  /* Convert HRP to lowercase and copy to output */
  char hrp_lower[ 32 ];
  for( ulong i = 0; i < hrp_len; i++ ) {
    hrp_lower[ i ] = (char)tolower( (uchar)hrp[ i ] );
    out[ i ] = hrp_lower[ i ];
  }
  hrp_lower[ hrp_len ] = '\0';
  out[ hrp_len ] = AT_BECH32_SEPARATOR;

  /* Create checksum */
  uchar checksum[ AT_BECH32_CHECKSUM_LEN ];
  at_bech32_create_checksum( checksum, hrp_lower, data, data_sz );

  /* Encode data + checksum using charset */
  ulong pos = hrp_len + 1;
  for( ulong i = 0; i < data_sz; i++ ) {
    if( data[ i ] >= AT_BECH32_CHARSET_LEN ) {
      return AT_BECH32_ERR_DATA_INVALID;
    }
    out[ pos++ ] = charset[ data[ i ] ];
  }
  for( int i = 0; i < AT_BECH32_CHECKSUM_LEN; i++ ) {
    out[ pos++ ] = charset[ checksum[ i ] ];
  }
  out[ pos ] = '\0';

  return (int)(pos);
}

int
at_bech32_decode( char const * bech,
                  char *       hrp_out,
                  ulong        hrp_out_sz,
                  uchar *      data_out,
                  ulong *      data_out_sz ) {
  ulong bech_len = at_strlen( bech );

  /* Check for mixed case */
  int has_upper = 0, has_lower = 0;
  for( ulong i = 0; i < bech_len; i++ ) {
    if( bech[ i ] >= 'A' && bech[ i ] <= 'Z' ) has_upper = 1;
    if( bech[ i ] >= 'a' && bech[ i ] <= 'z' ) has_lower = 1;
  }
  if( has_upper && has_lower ) {
    return AT_BECH32_ERR_HRP_MIX_CASE;
  }

  /* Find separator (last occurrence of '1') */
  long sep_pos = -1;
  for( long i = (long)bech_len - 1; i >= 0; i-- ) {
    if( bech[ i ] == AT_BECH32_SEPARATOR ) {
      sep_pos = i;
      break;
    }
  }
  if( sep_pos < 0 ) {
    return AT_BECH32_ERR_SEPARATOR_MISSING;
  }
  if( sep_pos < 1 || (ulong)sep_pos + 7 > bech_len ) {
    return AT_BECH32_ERR_SEPARATOR_POS;
  }

  /* Extract and validate HRP */
  ulong hrp_len = (ulong)sep_pos;
  if( hrp_out_sz < hrp_len + 1 ) {
    return AT_BECH32_ERR_BUFFER_TOO_SMALL;
  }
  for( ulong i = 0; i < hrp_len; i++ ) {
    char c = bech[ i ];
    if( c < 33 || c > 126 ) {
      return AT_BECH32_ERR_HRP_INVALID_CHAR;
    }
    hrp_out[ i ] = (char)tolower( (uchar)c );
  }
  hrp_out[ hrp_len ] = '\0';

  /* Decode data part */
  ulong data_len = bech_len - hrp_len - 1;
  if( *data_out_sz < data_len - AT_BECH32_CHECKSUM_LEN ) {
    return AT_BECH32_ERR_BUFFER_TOO_SMALL;
  }

  uchar data_5bit[ 256 ];
  for( ulong i = 0; i < data_len; i++ ) {
    char c = bech[ hrp_len + 1 + i ];
    if( c < 0 || (uchar)c >= 128 ) {
      return AT_BECH32_ERR_HRP_INVALID_CHAR;
    }
    uchar val = charset_rev[ (uchar)c ];
    if( val == 255 ) {
      return AT_BECH32_ERR_HRP_INVALID_CHAR;
    }
    data_5bit[ i ] = val;
  }

  /* Verify checksum */
  if( !at_bech32_verify_checksum_internal( hrp_out, data_5bit, data_len ) ) {
    return AT_BECH32_ERR_CHECKSUM_INVALID;
  }

  /* Copy data (excluding checksum) */
  ulong payload_len = data_len - AT_BECH32_CHECKSUM_LEN;
  at_memcpy( data_out, data_5bit, payload_len );
  *data_out_sz = payload_len;

  return AT_BECH32_OK;
}

int
at_bech32_verify_checksum( char const * bech ) {
  char hrp[ 16 ];
  uchar data[ 256 ];
  ulong data_sz = sizeof( data );

  int ret = at_bech32_decode( bech, hrp, sizeof( hrp ), data, &data_sz );
  return ret == AT_BECH32_OK;
}

int
at_bech32_address_encode( char *       out,
                          ulong        out_sz,
                          int          mainnet,
                          uchar const  public_key[ 32 ] ) {
  /* TOS address format:
     - 32-byte public key
     - Address type byte (0 = Normal) */

  uchar raw[ 33 ];
  at_memcpy( raw, public_key, 32 );
  raw[ 32 ] = 0;  /* AddressType::Normal */

  /* Convert 8-bit to 5-bit */
  uchar data_5bit[ 64 ];
  ulong data_5bit_sz = sizeof( data_5bit );
  int ret = at_bech32_convert_bits( data_5bit, &data_5bit_sz, 5, raw, 33, 8, 1 );
  if( ret != AT_BECH32_OK ) {
    return ret;
  }

  /* Encode with appropriate prefix */
  char const * hrp = mainnet ? AT_BECH32_TOS_MAINNET : AT_BECH32_TOS_TESTNET;
  return at_bech32_encode( out, out_sz, hrp, data_5bit, data_5bit_sz );
}

int
at_bech32_address_decode( char const * address,
                          int *        mainnet,
                          uchar        public_key[ 32 ] ) {
  char hrp[ 16 ];
  uchar data_5bit[ 64 ];
  ulong data_5bit_sz = sizeof( data_5bit );

  /* Decode Bech32 */
  int ret = at_bech32_decode( address, hrp, sizeof( hrp ), data_5bit, &data_5bit_sz );
  if( ret != AT_BECH32_OK ) {
    return ret;
  }

  /* Check prefix */
  if( at_strcmp( hrp, AT_BECH32_TOS_MAINNET ) == 0 ) {
    *mainnet = 1;
  } else if( at_strcmp( hrp, AT_BECH32_TOS_TESTNET ) == 0 ) {
    *mainnet = 0;
  } else {
    return AT_BECH32_ERR_HRP_INVALID_CHAR;
  }

  /* Convert 5-bit to 8-bit */
  uchar raw[ 64 ];
  ulong raw_sz = sizeof( raw );
  ret = at_bech32_convert_bits( raw, &raw_sz, 8, data_5bit, data_5bit_sz, 5, 0 );
  if( ret != AT_BECH32_OK ) {
    return ret;
  }

  /* Check address type and extract public key */
  if( raw_sz < 33 || raw[ 32 ] != 0 ) {
    return AT_BECH32_ERR_DATA_INVALID;
  }

  at_memcpy( public_key, raw, 32 );
  return AT_BECH32_OK;
}