# Avatar src/crypto/ed25519/Local.mk

$(call add-hdrs,../at_ed25519.h ../at_x25519.h ../at_f25519.h ../at_f25519_ref.h)
$(call add-hdrs,../at_curve25519.h ../at_curve25519_ref.h ../at_curve25519_scalar.h ../at_ristretto255.h ../at_elgamal.h)
$(call add-objs,at_f25519 at_curve25519 at_curve25519_scalar at_ed25519_user at_x25519 at_ristretto255 at_elgamal,at_crypto)
# Note: at_curve25519_secure includes ref/ internally
# Note: at_curve25519_tables is a generator utility, not compiled normally

# AVX2 optimized Curve25519 (r2526x10 representation)
# Requires AVX2 (Haswell+ 2013)
$(call add-mk,avx2)

# AVX-512F optimized Curve25519 (r2526x8 representation)
# Requires AVX-512F but NOT IFMA (Skylake-X, Cascade Lake)
# Scales up AVX2 algorithm from 4-way to 8-way parallelism
$(call add-mk,avx512_general)

# AVX-512 IFMA optimized Curve25519 (r43x6 representation)
# Requires AVX-512 VBMI and IFMA extensions (Ice Lake+)
ifeq ($(AT_HAS_AVX512_IFMA),1)
$(call add-objs,avx512_ifma/at_r43x6 avx512_ifma/at_r43x6_ge avx512_ifma/at_f25519,at_crypto)
endif

# Tests are in src/test/
# $(call make-unit-test,test_ed25519,test_ed25519,at_crypto at_util)