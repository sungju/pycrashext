"""
Name resolution and HTTP POST helpers for the commands that talk to remoteapi.

This module deliberately imports nothing from pykdump. Some callers - disasm.py
and ai_send.py - are launched by a shell escape into the *system* python3
("!echo ... | python3 disasm.py"), which has no pykdump at all, so anything
they import has to work outside crash as well as inside it.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import os
import socket
import struct
import random
import subprocess
import urllib.request
import urllib.parse
import urllib.error


#
# Why any of this is needed.
#
# crash runs PyKdump's bundled Python, which is statically linked. glibc
# answers getaddrinfo() by dlopen()ing the NSS modules named in
# /etc/nsswitch.conf - libnss_files.so, libnss_dns.so - and a static
# interpreter cannot load them. Name lookups then fail with 'Name or service
# not known' (EAI_NONAME, errno -2) inside crash even though curl, ping and
# the system python3 on the very same host resolve the name fine.
#
# Sockets themselves work, so the way out is to answer the question without
# getaddrinfo(): read /etc/hosts, ask a resolver binary that is dynamically
# linked and therefore still has NSS, or speak DNS to the nameservers in
# /etc/resolv.conf directly. Each path only ever hands a numeric address to
# the socket layer, which never involves NSS.
#

# remoteapi refuses requests without this key once the server sets one.
API_KEY_VAR = "PYCRASHEXT_API_KEY"

DNS_PORT = 53
DNS_TIMEOUT = 2
DNS_TYPE_A = 1
DNS_CLASS_IN = 1
COMMAND_TIMEOUT = 5

HOSTNAME_CHARS = set("abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                     "0123456789-._")


def note(trace, message):
    """Record a resolution step, so a failure can say what it actually tried."""
    if trace is not None:
        trace.append(message)


def is_valid_hostname(hostname):
    """True if 'hostname' is safe to hand to a resolver command.

    Everything here eventually reaches argv, so a name is only ever passed on
    when it looks like a name. Nothing shells out with a string the user could
    have loaded with metacharacters via CRASHEXT_SERVER.
    """
    if not hostname or len(hostname) > 253:
        return False

    for char in hostname:
        if char not in HOSTNAME_CHARS:
            return False

    return True


def is_ipv4_address(text):
    """True if 'text' is a dotted-quad, checked without any name lookup."""
    parts = text.split(".")
    if len(parts) != 4:
        return False

    for part in parts:
        if not part.isdigit() or len(part) > 3:
            return False
        if int(part) > 255:
            return False

    return True


def is_numeric_host(hostname):
    """True if 'hostname' is already a literal address, so needs no lookup."""
    if is_ipv4_address(hostname):
        return True

    # inet_pton is the only way to recognise IPv6, but a static build may not
    # export it; a missing IPv6 check is better than an exception here.
    try:
        socket.inet_pton(socket.AF_INET6, hostname)
        return True
    except Exception:
        return False


def first_ipv4_in(text):
    """First dotted-quad appearing in 'text', or None.

    Resolver commands each have their own output format - 'has address',
    'Address:', a bare list - so pick the address out rather than trying to
    parse five different layouts.
    """
    if not text:
        return None

    for line in text.splitlines():
        # 'nslookup' echoes the server it asked before giving the answer
        if line.lower().startswith("server"):
            continue
        for word in line.replace(",", " ").split():
            word = word.strip("()<>[]")
            if is_ipv4_address(word):
                return word

    return None


def resolve_from_hosts_file(hostname, path="/etc/hosts", trace=None):
    """Address for 'hostname' out of /etc/hosts, or None if it is not there."""
    wanted = hostname.rstrip(".").lower()

    try:
        with open(path) as f:
            lines = f.readlines()
    except Exception as e:
        note(trace, "%s: cannot read (%s)" % (path, e))
        return None

    for line in lines:
        fields = line.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        for name in fields[1:]:
            if name.rstrip(".").lower() == wanted:
                note(trace, "%s: found %s" % (path, fields[0]))
                return fields[0]

    note(trace, "%s: no entry for '%s'" % (path, hostname))
    return None


def get_resolv_conf_nameservers(path="/etc/resolv.conf"):
    """Nameserver addresses listed in /etc/resolv.conf, in order."""
    servers = []

    try:
        with open(path) as f:
            lines = f.readlines()
    except Exception:
        return servers

    for line in lines:
        fields = line.split("#", 1)[0].split(";", 1)[0].split()
        if len(fields) >= 2 and fields[0] == "nameserver":
            servers.append(fields[1])

    return servers


def get_resolv_conf_search(path="/etc/resolv.conf"):
    """Search domains from /etc/resolv.conf, for unqualified names."""
    domains = []

    try:
        with open(path) as f:
            lines = f.readlines()
    except Exception:
        return domains

    for line in lines:
        fields = line.split("#", 1)[0].split(";", 1)[0].split()
        if len(fields) >= 2 and fields[0] in ("search", "domain"):
            domains.extend(fields[1:])

    return domains


def run_resolver_command(argv):
    """Run a resolver command and return its output, or None if it is unusable."""
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        out, _err = proc.communicate(timeout=COMMAND_TIMEOUT)
        return out.decode("utf-8", "replace")
    except Exception:
        return None


def resolve_via_command(hostname, trace=None):
    """Address for 'hostname' from a dynamically linked resolver binary.

    The NSS problem is confined to this one statically linked interpreter.
    Every ordinary binary on the host - getent, dig, even the system python3 -
    still resolves names correctly, so borrowing one of them is both the most
    reliable fallback and the closest thing to what the user would get by
    running the lookup by hand.
    """
    if not is_valid_hostname(hostname):
        note(trace, "commands: skipped, '%s' is not a plain hostname"
             % hostname)
        return None

    attempts = [
        ["getent", "ahostsv4", hostname],
        ["getent", "hosts", hostname],
        ["dig", "+short", "+time=2", "+tries=1", hostname, "A"],
        ["host", "-t", "A", hostname],
        ["nslookup", "-type=A", hostname],
        ["python3", "-c",
         "import socket;print(socket.gethostbyname(%r))" % hostname],
    ]

    for argv in attempts:
        output = run_resolver_command(argv)
        if output is None:
            continue
        address = first_ipv4_in(output)
        if address is not None:
            note(trace, "%s: found %s" % (argv[0], address))
            return address
        note(trace, "%s: no address in reply" % argv[0])

    return None


def encode_dns_name(hostname):
    """Wire form of a domain name: length-prefixed labels, NUL terminated."""
    encoded = b""

    for label in hostname.rstrip(".").split("."):
        raw = label.encode("ascii")
        if len(raw) == 0 or len(raw) > 63:
            raise ValueError("bad label in '%s'" % hostname)
        encoded = encoded + struct.pack("B", len(raw)) + raw

    return encoded + b"\x00"


def skip_dns_name(data, offset):
    """Offset just past the name at 'offset', following no compression pointer.

    A pointer ends the name, so its two bytes are all that has to be stepped
    over; the target does not have to be read to know where the record
    continues.
    """
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if (length & 0xc0) == 0xc0:
            return offset + 2
        offset = offset + 1 + length

    raise ValueError("truncated name in DNS response")


def parse_dns_response(data, query_id):
    """First A record in a DNS response, as a dotted-quad string, or None.

    This parses a packet off the network, so it treats every length in it as
    hostile and answers None for anything it cannot make sense of rather than
    letting a malformed response raise into the caller.
    """
    if len(data) < 12:
        return None

    try:
        resp_id, flags, qdcount, ancount = struct.unpack(">HHHH", data[:8])

        if resp_id != query_id:
            return None
        if (flags & 0x8000) == 0:       # not a response
            return None
        if (flags & 0x000f) != 0:       # RCODE says the server refused it
            return None

        offset = 12
        for _ in range(qdcount):
            offset = skip_dns_name(data, offset)
            offset = offset + 4         # QTYPE + QCLASS

        for _ in range(ancount):
            offset = skip_dns_name(data, offset)
            if offset + 10 > len(data):
                return None
            rtype, rclass, _ttl, rdlength = \
                struct.unpack(">HHIH", data[offset:offset + 10])
            offset = offset + 10
            if offset + rdlength > len(data):
                return None
            if rtype == DNS_TYPE_A and rclass == DNS_CLASS_IN \
                    and rdlength == 4:
                return socket.inet_ntoa(data[offset:offset + 4])
            offset = offset + rdlength  # CNAME and friends: keep looking
    except Exception:
        return None

    return None


def query_dns_server(hostname, server, timeout=DNS_TIMEOUT):
    """Ask one nameserver for the A record of 'hostname' over UDP."""
    query_id = random.randint(0, 0xffff)

    try:
        question = encode_dns_name(hostname)
    except Exception:
        return None

    packet = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0) \
        + question + struct.pack(">HH", DNS_TYPE_A, DNS_CLASS_IN)

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (server, DNS_PORT))
        data, _addr = sock.recvfrom(4096)
        return parse_dns_response(data, query_id)
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def resolve_via_dns(hostname, trace=None):
    """Address for 'hostname' by querying /etc/resolv.conf's nameservers."""
    servers = get_resolv_conf_nameservers()
    if len(servers) == 0:
        note(trace, "/etc/resolv.conf: no nameserver lines (or unreadable)")
        return None

    candidates = [hostname]
    if "." not in hostname.rstrip("."):
        for domain in get_resolv_conf_search():
            candidates.append("%s.%s" % (hostname.rstrip("."),
                                         domain.rstrip(".")))

    for candidate in candidates:
        for server in servers:
            address = query_dns_server(candidate, server)
            if address is not None:
                note(trace, "DNS %s: %s is %s"
                     % (server, candidate, address))
                return address
            note(trace, "DNS %s: no answer for %s" % (server, candidate))

    return None


def resolve_host(hostname, trace=None):
    """Address for 'hostname' without calling getaddrinfo(), or None.

    Cheapest first: a literal address needs nothing, /etc/hosts is a file
    read, a resolver binary costs a fork but is the most likely to succeed,
    and a direct DNS query is the last resort for a host too stripped down to
    have any of those binaries.
    """
    if hostname is None or hostname == "":
        return None

    if is_numeric_host(hostname):
        return hostname

    address = resolve_from_hosts_file(hostname, trace=trace)
    if address is not None:
        return address

    address = resolve_via_command(hostname, trace=trace)
    if address is not None:
        return address

    return resolve_via_dns(hostname, trace=trace)


def url_with_resolved_host(url, trace=None):
    """'url' with its hostname replaced by an address, plus the original host.

    Returns (rewritten_url, original_netloc), or (None, None) when the name
    cannot be resolved or there is nothing to rewrite. The caller must send
    the original netloc back as the Host: header, or every name-based virtual
    host on the far end will answer with the wrong site.
    """
    try:
        parts = urllib.parse.urlsplit(url)
        hostname = parts.hostname
    except Exception:
        return None, None

    if hostname is None or is_numeric_host(hostname):
        return None, None

    address = resolve_host(hostname, trace=trace)
    if address is None:
        return None, None

    netloc = address
    if parts.port is not None:
        netloc = "%s:%d" % (address, parts.port)
    if parts.username is not None:
        userinfo = parts.username
        if parts.password is not None:
            userinfo = "%s:%s" % (userinfo, parts.password)
        netloc = "%s@%s" % (userinfo, netloc)

    rewritten = urllib.parse.urlunsplit((parts.scheme, netloc, parts.path,
                                         parts.query, parts.fragment))

    return rewritten, parts.netloc


def is_dns_failure(reason):
    """True if a URLError reason is a name-lookup failure, not a refusal.

    Worth separating: 'connection refused' means the server is down, but
    'name or service not known' from inside crash almost always means the
    static interpreter cannot reach NSS, and the host is perfectly fine.
    """
    if isinstance(reason, socket.gaierror):
        return True

    text = str(reason).lower()

    return ("name or service not known" in text
            or "nodename nor servname" in text
            or "temporary failure in name resolution" in text)


def post_url(url, encoded_data, timeout=None, host_header=None):
    """POST 'encoded_data' to 'url', optionally overriding the Host: header.

    Sends PYCRASHEXT_API_KEY as the X-API-Key header when it is set, which
    is what the remoteapi server checks when it has a key of its own.
    """
    req = urllib.request.Request(url, data=encoded_data, method='POST')
    api_key = os.environ.get(API_KEY_VAR, "")
    if api_key:
        req.add_header('X-API-Key', api_key)
    if host_header is not None:
        # The URL now carries an address rather than a name, so the name has
        # to travel in the header instead, or a name-based virtual host on
        # the far end will serve the wrong site - or refuse outright.
        req.add_header('Host', host_header)

    if timeout is None:
        return urllib.request.urlopen(req)

    return urllib.request.urlopen(req, timeout=timeout)


def urlopen_post(url, encoded_data, timeout=None, verbose=False, trace=None):
    """POST to 'url', falling back to a hand-resolved address on DNS failure.

    Behaves exactly like urlopen() for callers: the response on success, and
    the original exception on failure, so existing error handling still
    applies. The only difference is that a name lookup which failed purely
    because the interpreter cannot reach NSS gets a second chance.
    """
    try:
        return post_url(url, encoded_data, timeout)
    except urllib.error.HTTPError:
        raise                           # a real answer, just not a 200
    except urllib.error.URLError as e:
        if not is_dns_failure(e.reason):
            raise

        resolved_url, host_header = url_with_resolved_host(url, trace=trace)
        if resolved_url is None:
            raise

        if verbose:
            print("Name lookup failed; retrying via %s" % resolved_url)

        try:
            return post_url(resolved_url, encoded_data, timeout, host_header)
        except Exception as retry_error:
            note(trace, "retry via %s failed: %s"
                 % (resolved_url, retry_error))

        # Report what the caller actually asked for, not the retry's failure
        raise e


def api_key_hint(error):
    """What a 401 from remoteapi means for the key, or '' for other errors."""
    if getattr(error, "code", None) != 401:
        return ""
    if os.environ.get(API_KEY_VAR, ""):
        return ("The server rejected the API key: %s does not match the "
                "server's key." % API_KEY_VAR)
    return ("The server requires an API key: set %s to the server's key."
            % API_KEY_VAR)


def print_dns_failure_help(url, reason, trace=None):
    """Explain a name-lookup failure, which is rarely what it looks like."""
    host = None
    try:
        host = urllib.parse.urlsplit(url).hostname
    except Exception:
        pass

    print("\nCannot resolve the server's hostname%s."
          % ("" if host is None else " '%s'" % host))
    print("Server address is <%s>" % url)
    print("\nError: %s" % str(reason))

    if trace:
        print("\nThe fallback resolver tried:")
        for line in trace:
            print("  - %s" % line)

    print("\nIf the same name resolves fine outside crash - with curl, ping")
    print("or host - then the network is healthy and this is crash's own")
    print("Python:")
    print("  - PyKdump's interpreter is statically linked, and glibc resolves")
    print("    names by dlopen()ing the NSS modules, which a static binary")
    print("    cannot do. Name lookups fail even though sockets work.")
    print("  - Or crash is running in a chroot or container (a retrace")
    print("    server, say) that has no /etc/resolv.conf.")
    print("\nWorkaround: put the address in CRASHEXT_SERVER instead of the")
    print("name, resolved on this host rather than elsewhere:")
    if host is not None:
        print("  $ getent hosts %s" % host)
        print("  $ dig +short %s" % host)
    print("  $ export CRASHEXT_SERVER=http://<address>:<port>")
