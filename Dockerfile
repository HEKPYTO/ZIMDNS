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

RUN addgroup -S -g 10001 zimdns \
    && adduser -S -D -H -u 10001 -G zimdns zimdns \
    && mkdir -p /etc/zimdns /run/zimdns \
    && chown -R zimdns:zimdns /etc/zimdns /run/zimdns

COPY --from=build /workspace/zig-out/bin/zimdns /usr/local/bin/zimdns
COPY examples/config.gdns /etc/zimdns/config.gdns
COPY examples/blocklists /examples/blocklists
COPY examples/zones /examples/zones

USER 10001:10001
WORKDIR /
EXPOSE 1053/udp
VOLUME ["/etc/zimdns"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/zimdns", "query", "@127.0.0.1", "-p", "1053", "dns.home.arpa.", "A"]

ENTRYPOINT ["/usr/local/bin/zimdns"]
# Relative --config path: the loader confines all paths beneath the working directory and rejects absolute paths.
CMD ["server", "run", "--config", "etc/zimdns/config.gdns", "--serve-udp"]
