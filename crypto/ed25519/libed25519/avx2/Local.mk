# Avatar src/crypto/ed25519/avx2/Local.mk
# AVX2 optimized Curve25519/Ed25519 using radix-2^25.5 representation
# Works on Haswell+ (2013+) CPUs with AVX2 support
# Disabled when AVX-512 IFMA or AVX-512 General are available

$(call add-hdrs,at_r2526x10.h at_f25519.h at_curve25519.h)

ifeq ($(AT_HAS_AVX),1)
ifneq ($(AT_HAS_AVX512_IFMA),1)
ifneq ($(AT_HAS_AVX512_GENERAL),1)
$(call add-objs,at_r2526x10 at_curve25519,at_crypto)
endif
endif
endif
