# Vendored QUIC / HTTP/3 sources

- ngtcp2 1.26.0 — https://github.com/ngtcp2/ngtcp2/releases/download/v1.26.0/ngtcp2-1.26.0.tar.xz — MIT (see `ngtcp2/COPYING`).
  SHA-256 `7804aa0fa1c39942ba322a90805824c37231f7675b08d0c3cc4332858a7b085e`.
  Copied: `lib/` (all C sources and headers), `lib/includes/`, `crypto/shared.c`,
  `crypto/shared.h`, `crypto/gnutls/`, `crypto/includes/`.
- nghttp3 1.19.0 — https://github.com/ngtcp2/nghttp3/releases/download/v1.19.0/nghttp3-1.19.0.tar.xz — MIT (see `nghttp3/COPYING`).
  SHA-256 `228e17f5cc3d4de7bfced9912bd09de30e7f45741cc47503cf88d3fa9209e155`.
  Copied: `lib/`, `lib/includes/`.

Both release tarballs were extracted and compared against the vendored trees:
every copied source and header was byte-identical except the two local patches
below; only the autotools/CMake files were omitted. The licenses match the
release `COPYING` files byte-for-byte.

Local patches beyond the release tarballs (required for -Wall -Wextra -Werror):
- `ngtcp2/lib/ngtcp2_unreachable.c` — `(void)file; (void)line; (void)func;` at
  the top of `ngtcp2_unreachable_fail`, silencing -Wunused-parameter when
  NGTCP2_UNREACHABLE_LOG is undefined (this build defines no config.h).
- `nghttp3/lib/nghttp3_unreachable.c` — same `(void)` casts in
  `nghttp3_unreachable_fail` for NGHTTP3_UNREACHABLE_LOG.

Only the GnuTLS crypto backend is vendored; the OpenSSL/BoringSSL/PicoTLS/QuicTLS/wolfSSL
backends were dropped. No `config.h` is generated (`HAVE_CONFIG_H` is not defined);
the checked-in `ngtcp2/lib/includes/ngtcp2/version.h` supplies the version.
