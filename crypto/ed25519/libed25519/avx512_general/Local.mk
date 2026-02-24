# Avatar src/crypto/ed25519/avx512_general/Local.mk
# AVX-512F (non-IFMA) optimized Curve25519/Ed25519 using radix-2^25.5 representation
# Works on Skylake-X/Cascade Lake CPUs with AVX-512F but WITHOUT AVX-512 IFMA
# This is the same algorithm as AVX2 but scaled up from 4-way to 8-way parallelism

$(call add-hdrs,at_r2526x8.h at_f25519.h)

ifeq ($(AT_HAS_AVX512),1)
ifeq ($(AT_HAS_AVX512_GENERAL),1)
$(call add-objs,at_r2526x8,at_crypto)

# Unit tests for AVX-512F General field arithmetic
$(call make-unit-test,test_avx512_general_field,test_avx512_general_field,at_crypto at_util)
$(call make-unit-test,test_avx512_general_vs_ref,test_avx512_general_vs_ref,at_crypto at_util)
$(call make-unit-test,test_avx512_general_higher_ops,test_avx512_general_higher_ops,at_crypto at_util)
endif
endif
