FROM alpine:3.22 AS build

ARG TARGETARCH
ARG ZIG_VERSION=0.16.0
ARG ZIG_X86_64_SHA=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
ARG ZIG_AARCH64_SHA=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17

RUN apk add --no-cache ca-certificates tar wget xz

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

WORKDIR /workspace
COPY . .
RUN /opt/zig/zig build -Doptimize=ReleaseSafe

FROM alpine:3.22 AS runtime

RUN addgroup -S -g 10001 gcli-dns \
    && adduser -S -D -H -u 10001 -G gcli-dns gcli-dns \
    && mkdir -p /etc/gcli-dns /var/lib/gcli-dns /run/gcli-dns \
    && chown -R gcli-dns:gcli-dns /etc/gcli-dns /var/lib/gcli-dns /run/gcli-dns

COPY --from=build /workspace/zig-out/bin/gcli-dns /usr/local/bin/gcli-dns
COPY examples/config.gdns /etc/gcli-dns/config.gdns

USER 10001:10001
EXPOSE 1053/udp 1053/tcp 853/tcp 8443/tcp 8853/udp
VOLUME ["/etc/gcli-dns", "/var/lib/gcli-dns"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/gcli-dns", "--help"]

ENTRYPOINT ["/usr/local/bin/gcli-dns"]
CMD ["--help"]

