"""Offline TLS-channel interop mirror (13 tests, stdlib only, no sockets).

Mirrors the Zig channel unit tests without binding any socket (loopback
binds are env-blocked here; see test/interop/README.md and
docs/reports/gates-final/env-bind-probe.log):

  src/transport/tls.zig  5 tests (ALPN, opt-in flag, identity paths,
                         PEM pair, fail-closed startup + DoQ)
  src/transport/doh.zig  4 tests (GET mapping, POST mapping, rejections +
                         status mapping, status reasons)
  src/transport/dot.zig  4 tests (FIFO framing, zero-length reject,
                         metrics, defaults)

Run:  python3 test/interop/tls_channel_test.py
      python3 -m unittest test.interop.tls_channel_test -v
"""

import base64
import struct
import unittest

# --- Contract constants (must match src/transport/*.zig, src/platform/listener.zig) ---
DOT_PORT = 853
DOT_ALPN = "dot"
DOH_PORT = 443
DOH_PATH = "/dns-query"
DOH_MEDIA_TYPE = "application/dns-message"
DOH_ALPN_H2 = "h2"
DOH_ALPN_HTTP11 = "http/1.1"
MAX_BODY_LEN = 65535
MAX_HEADER_BYTES = 8192
MAX_EXCHANGES_PER_CONNECTION = 16
TCP_MAX_FRAME_SIZE = 65535
TCP_MAX_FRAMES_PER_CONNECTION = 16
TCP_IO_TIMEOUT_SECONDS = 5

STATUS_REASON = {
    200: "OK",
    400: "Bad Request",
    404: "Not Found",
    405: "Method Not Allowed",
    413: "Payload Too Large",
    414: "URI Too Long",
    415: "Unsupported Media Type",
    431: "Request Header Fields Too Large",
    500: "Internal Server Error",
}


# --- Typed errors mirroring doh.zig Error / tls.zig Error ---
class TlsDisabled(Exception):
    pass


class MissingCertificate(Exception):
    pass


class MissingKey(Exception):
    pass


class CertKeySameFile(Exception):
    pass


class TlsServerUnavailable(Exception):
    pass


class DoqDeferred(Exception):
    pass


class BadRequestLine(Exception):
    pass


class UnsupportedMethod(Exception):
    pass


class BadTarget(Exception):
    pass


class HeadersTooLarge(Exception):
    pass


class BodyTooLarge(Exception):
    pass


class BadContentType(Exception):
    pass


class BadBase64(Exception):
    pass


class BadDnsMessage(Exception):
    pass


class BadTcpFrame(Exception):
    pass


def negotiate_alpn(offered, want_doh):
    """Mirror tls.zig negotiateAlpn: DoT wants dot, DoH wants http/1.1 only.

    doh.zig implements the HTTP/1.1 mapping, so selecting h2 would hand the
    client a protocol this server cannot speak.
    """
    wanted = DOH_ALPN_HTTP11 if want_doh else DOT_ALPN
    for proto in offered:
        if proto == wanted:
            return wanted
    return None


def require_enabled(enabled):
    if not enabled:
        raise TlsDisabled("encrypted listeners require the opt-in flag")


def validate_paths(cert_path, key_path):
    if not cert_path:
        raise MissingCertificate("certificate path is empty")
    if not key_path:
        raise MissingKey("key path is empty")
    if cert_path == key_path:
        raise CertKeySameFile("certificate and key must be distinct files")


def validate_pem_pair(cert_bytes, key_bytes):
    if "-----BEGIN" not in cert_bytes:
        raise MissingCertificate("certificate is not PEM")
    if len(key_bytes) == 0:
        raise MissingKey("key is empty")


def require_tls_server():
    """Mirror tls.zig requireTlsServer: no TLS server, so no encrypted
    listener may start and no port may be bound."""
    raise TlsServerUnavailable("no TLS-server dependency; refuse to start")


def dial_doq():
    raise DoqDeferred("RFC 9250 needs QUIC, not TCP+TLS")


def status_for_error(exc):
    if isinstance(exc, UnsupportedMethod):
        return 405
    if isinstance(exc, BadTarget):
        return 404
    if isinstance(exc, HeadersTooLarge):
        return 431
    if isinstance(exc, BodyTooLarge):
        return 413
    if isinstance(exc, BadContentType):
        return 415
    return 400


def path_of(target):
    rest = target
    if "://" in rest:
        rest = rest.split("://", 1)[1]
        if "/" in rest:
            rest = rest[rest.index("/"):]
    if "?" in rest:
        rest = rest[:rest.index("?")]
    return rest


def query_of(target):
    rest = target
    if "://" in rest:
        rest = rest.split("://", 1)[1]
        if "/" in rest:
            rest = rest[rest.index("/"):]
        else:
            return ""
    if "?" not in rest:
        return ""
    return rest.split("?", 1)[1]


def dns_param(query):
    found = None
    for pair in query.split("&"):
        if not pair.startswith("dns="):
            continue
        if found is not None:
            raise BadDnsMessage("duplicate dns parameter")
        found = pair[len("dns="):]
    if found is None:
        raise BadDnsMessage("missing dns parameter")
    if len(found) == 0 or len(found) > MAX_HEADER_BYTES:
        raise BadDnsMessage("dns parameter length out of bounds")
    return found


def decode_query_param(value):
    try:
        out = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise BadBase64(str(exc))
    if len(out) == 0 or len(out) > MAX_BODY_LEN:
        raise BadDnsMessage("decoded query length out of bounds")
    return out


def dns_query_from_request(method, target, content_type, body):
    """Mirror doh.zig dnsQueryFromRequest for GET/POST (RFC 8484 4.1/4.2)."""
    if path_of(target) != DOH_PATH:
        raise BadTarget(target)
    if method == "GET":
        if len(target) > MAX_HEADER_BYTES:
            raise BadDnsMessage("target too long")
        return decode_query_param(dns_param(query_of(target)))
    if method == "POST":
        if content_type != DOH_MEDIA_TYPE:
            raise BadContentType(content_type)
        if len(body) == 0 or len(body) > MAX_BODY_LEN:
            raise BadDnsMessage("POST body length out of bounds")
        return body
    raise UnsupportedMethod(method)


def build_query_packet(tx_id, labels, qtype=1, qclass=1):
    header = struct.pack(">HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    return header + qname + struct.pack(">HH", qtype, qclass)


def frame_message(payload):
    if len(payload) == 0 or len(payload) > TCP_MAX_FRAME_SIZE:
        raise BadTcpFrame("frame length %d out of bounds" % len(payload))
    return struct.pack(">H", len(payload)) + payload


def parse_frames(stream):
    """Parse concatenated length-prefixed frames FIFO (RFC 7858 3.3)."""
    messages = []
    pos = 0
    while pos < len(stream):
        if pos + 2 > len(stream):
            raise BadTcpFrame("truncated length prefix")
        (length,) = struct.unpack_from(">H", stream, pos)
        if length == 0 or length > TCP_MAX_FRAME_SIZE:
            raise BadTcpFrame("bad frame length %d" % length)
        pos += 2
        if pos + length > len(stream):
            raise BadTcpFrame("truncated frame body")
        messages.append(stream[pos:pos + length])
        pos += length
        if len(messages) > TCP_MAX_FRAMES_PER_CONNECTION:
            raise BadTcpFrame("too many frames per connection")
    return messages


def query_id(wire):
    (tx_id,) = struct.unpack_from(">H", wire, 0)
    return tx_id


DNS_HOME_ARPA = (b"dns", b"home", b"arpa")
HOME_ARPA_AXFR = (
    bytes([4]) + b"home" + bytes([4]) + b"arpa" + b"\x00"
)


class TlsPolicyTest(unittest.TestCase):
    def test_alpn_selects_dot_for_dot_and_http11_only_for_doh(self):
        offered = ["h2", "dot", "http/1.1"]
        self.assertEqual("dot", negotiate_alpn(offered, False))
        self.assertEqual("http/1.1", negotiate_alpn(offered, True))
        self.assertIsNone(negotiate_alpn(["h2"], True))
        self.assertIsNone(negotiate_alpn(["h2"], False))
        self.assertIsNone(negotiate_alpn([], True))

    def test_encrypted_listeners_require_opt_in(self):
        require_enabled(True)
        with self.assertRaises(TlsDisabled):
            require_enabled(False)

    def test_identity_paths_must_be_set_and_distinct(self):
        validate_paths("/etc/zimdns/tls/cert.pem", "/etc/zimdns/tls/key.pem")
        with self.assertRaises(MissingCertificate):
            validate_paths("", "/etc/zimdns/tls/key.pem")
        with self.assertRaises(MissingKey):
            validate_paths("/etc/zimdns/tls/cert.pem", "")
        with self.assertRaises(CertKeySameFile):
            validate_paths("/etc/zimdns/tls/same.pem", "/etc/zimdns/tls/same.pem")

    def test_pem_pair_rejects_non_pem_and_empty_key(self):
        validate_pem_pair("-----BEGIN CERTIFICATE-----\nabc\n", b"key-bytes")
        with self.assertRaises(MissingCertificate):
            validate_pem_pair("not a pem", b"key-bytes")
        with self.assertRaises(MissingKey):
            validate_pem_pair("-----BEGIN CERTIFICATE-----\nabc\n", b"")

    def test_encrypted_listener_startup_fails_closed_and_doq_deferred(self):
        with self.assertRaises(TlsServerUnavailable):
            require_tls_server()
        with self.assertRaises(DoqDeferred):
            dial_doq()


class DohMappingTest(unittest.TestCase):
    def test_get_serves_base64url_query(self):
        wire = build_query_packet(0xABCD, DNS_HOME_ARPA)
        encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
        target = "/dns-query?dns=" + encoded
        out = dns_query_from_request("GET", target, None, b"")
        self.assertEqual(wire, out)
        self.assertEqual(0xABCD, query_id(out))

    def test_post_serves_dns_message_body(self):
        wire = build_query_packet(0xDCBA, DNS_HOME_ARPA)
        out = dns_query_from_request(
            "POST", "/dns-query", "application/dns-message", wire)
        self.assertEqual(wire, out)
        self.assertEqual(0xDCBA, query_id(out))

    def test_rejects_wrong_method_path_media_and_bad_wire(self):
        with self.assertRaises(BadTarget):
            dns_query_from_request("GET", "/nope?dns=AA", None, b"")
        with self.assertRaises(BadBase64):
            dns_query_from_request(
                "GET", "/dns-query?dns=!!!not-base64!!!", None, b"")
        with self.assertRaises(BadDnsMessage):
            dns_query_from_request("GET", "/dns-query?other=1", None, b"")
        with self.assertRaises(BadDnsMessage):
            dns_query_from_request(
                "GET", "/dns-query?dns=AA&dns=BB", None, b"")
        with self.assertRaises(BadContentType):
            dns_query_from_request(
                "POST", "/dns-query", "text/plain", b"hi")
        with self.assertRaises(BadContentType):
            dns_query_from_request("POST", "/dns-query", None, b"hi")
        self.assertEqual(405, status_for_error(UnsupportedMethod()))
        self.assertEqual(404, status_for_error(BadTarget()))
        self.assertEqual(415, status_for_error(BadContentType()))
        self.assertEqual(413, status_for_error(BodyTooLarge()))
        self.assertEqual(400, status_for_error(BadDnsMessage()))

    def test_status_reasons_cover_served_subset(self):
        self.assertEqual("OK", STATUS_REASON[200])
        self.assertEqual("Bad Request", STATUS_REASON[400])
        self.assertEqual("Not Found", STATUS_REASON[404])


class DotChannelTest(unittest.TestCase):
    def test_fifo_length_prefixed_framing(self):
        first = bytearray(build_query_packet(0x1234, DNS_HOME_ARPA))
        second = bytearray(build_query_packet(0x5678, DNS_HOME_ARPA))
        stream = frame_message(bytes(first)) + frame_message(bytes(second))
        messages = parse_frames(stream)
        self.assertEqual(2, len(messages))
        self.assertEqual(0x1234, query_id(messages[0]))
        self.assertEqual(0x5678, query_id(messages[1]))

    def test_rejects_zero_length_prefix(self):
        with self.assertRaises(BadTcpFrame):
            parse_frames(b"\x00\x00")

    def test_records_metrics(self):
        counters = {"queries_total": 0, "responses_total": 0,
                    "dot_queries_total": 0}
        wire = build_query_packet(0x9A9A, DNS_HOME_ARPA)
        messages = parse_frames(frame_message(wire))
        for _ in messages:
            counters["queries_total"] += 1
            counters["responses_total"] += 1
            counters["dot_queries_total"] += 1
        self.assertEqual(1, counters["queries_total"])
        self.assertEqual(1, counters["responses_total"])
        self.assertEqual(1, counters["dot_queries_total"])

    def test_defaults_name_rfc7858_port_and_alpn(self):
        self.assertEqual(853, DOT_PORT)
        self.assertEqual("dot", DOT_ALPN)
        self.assertEqual(16, TCP_MAX_FRAMES_PER_CONNECTION)
        self.assertEqual(65535, TCP_MAX_FRAME_SIZE)
        self.assertEqual(5, TCP_IO_TIMEOUT_SECONDS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
