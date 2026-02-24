# Avatar src/crypto/ed25519/avx512_ifma/Local.mk
# AVX-512 optimized Curve25519/Ed25519 using r43x6 representation
# Requires AVX-512 VBMI and IFMA extensions (Ice Lake+)
# Objects are added by parent Local.mk when AT_HAS_AVX512_IFMA=1

$(call add-hdrs,at_r43x6.h at_r43x6_inl.h at_r43x6_ge.h)
