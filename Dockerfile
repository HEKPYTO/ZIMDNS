FROM alpine:3.22 AS build

ARG TARGETARCH
ARG ZIG_VERSION=0.17.0
ARG ZIG_X86_64_SHA=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
ARG ZIG_AARCH64_SHA=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8

RUN apk add --no-cache ca-certificates gnutls-dev openssl-dev openssl tar wget xz

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) zig_arch="x86_64"; zig_sha="${ZIG_X86_64_SHA}" ;; \
        arm64) zig_arch="aarch64"; zig_sha="${ZIG_AARCH64_SHA}" ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    zig_url="https://ziglang.org/download/${ZIG_VERSION}/zig-${zig_arch}-linux-${ZIG_VERSION}.tar.xz"; \
    wget -O /tmp/zig.tar.xz "${zig_url}"; \
    echo "${zig_sha}  /tmp/zig.tar.xz" | sha256sum -c -; \
    mkdir -p /opt/zig; \
    tar -xf /tmp/zig.tar.xz -C /opt/zig --strip-components=1

ARG VERSION=0.1.0
WORKDIR /workspace
COPY . .
RUN /opt/zig/zig build -Doptimize=ReleaseSafe -Dversion="$VERSION"

FROM alpine:3.22 AS runtime

ARG VERSION=0.1.0
ARG REVISION=unknown
ARG SOURCE=unknown

# OpenSSL is linked dynamically, so the runtime keeps libssl/libcrypto
# beside the CA bundle the system-trust client paths verify against.
RUN apk add --no-cache ca-certificates gnutls libssl3 \
    && addgroup -S -g 10001 zimdns \
    && adduser -S -D -H -u 10001 -G zimdns zimdns \
    && mkdir -p /etc/zimdns /run/zimdns \
    && chown -R zimdns:zimdns /etc/zimdns /run/zimdns

COPY --from=build /workspace/zig-out/bin/zimdns /usr/local/bin/zimdns
COPY LICENSE /usr/share/doc/zimdns/AGPL-3.0-only.txt
COPY third_party/ngtcp2/COPYING /usr/share/doc/zimdns/ngtcp2-COPYING
COPY third_party/nghttp3/COPYING /usr/share/doc/zimdns/nghttp3-COPYING
COPY examples/config.gdns /etc/zimdns/config.gdns
COPY examples/blocklists /etc/zimdns/blocklists
COPY examples/zones /etc/zimdns/zones

LABEL org.opencontainers.image.title="zimdns" \
    org.opencontainers.image.version="${VERSION:-0.1.0}" \
    org.opencontainers.image.revision="${REVISION:-unknown}" \
    org.opencontainers.image.source="${SOURCE:-unknown}" \
    org.opencontainers.image.licenses="AGPL-3.0-only AND MIT"

USER 10001:10001
WORKDIR /
EXPOSE 1053/udp
EXPOSE 1053/tcp
VOLUME ["/etc/zimdns"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/zimdns", "query", "@127.0.0.1", "-p", "1053", "dns.home.arpa.", "A"]

ENTRYPOINT ["/usr/local/bin/zimdns"]
# Relative --config path: the loader confines all paths beneath the working directory and rejects absolute paths.
CMD ["server", "run", "--config", "etc/zimdns/config.gdns", "--serve-udp", "--serve-tcp"]
