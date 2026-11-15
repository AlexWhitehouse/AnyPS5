# libSceLibreSsl3

## remove | `SSL_get0_verified_chain` |

## remove | `SSL_get_peer_quic_transport_params` |

## add Functional

- [SSL_get0_verified_chain and SSL_get_peer_quic_transport_params](../../../core/libs/prx/libSceLibreSsl3/src/VerifiedChainQuicParams.cpp) - borrowed-pointer getters follow LibreSSL 4.0.0 [`ssl_lib.c`](https://github.com/libressl/openbsd/blob/ce488b78e0bd994780569df718596b9776ff681a/src/lib/libssl/ssl_lib.c). The unmeasured console SSL3_STATE layout uses the pinned `ssl_local.h` LP64 declarations: size 1016, verified chain at 520, peer QUIC parameters at 1000 and length at 1008. The existing 72-byte prefix is unchanged. Null SSLs, null QUIC outputs and a missing QUIC SSL3 state throw where upstream dereferences them; a missing verified-chain state returns null. No references are taken. Closes when: console layout and ABI are measured.
