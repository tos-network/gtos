#ifndef HEADER_at_src_util_at_util_h
#define HEADER_at_src_util_at_util_h

/*
Minimal at_util shim for GTOS vendored ed25519 build.

Avatar's full at_util.h pulls many subsystems (io/log/scratch/alloc/...) whose
objects are not linked in GTOS ed25519 cgo mode. For crypto/ed25519 we only
need base utility and bit helpers used by scalar/field code.
*/

#include "at_util_base.h"
#include "bits/at_bits.h"

#endif /* HEADER_at_src_util_at_util_h */
