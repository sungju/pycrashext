"""
Helper wrappers for running crash/gdb shell commands and reading structures.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *
from os.path import expanduser
import os
import sys
import time
import shlex
import tempfile
import socket
import struct
import random
import urllib.request
import urllib.parse
import urllib.error


def run_command_with_file(func, command, file_content):
    """exec_gdb_command() is failing to capture the output
    if the command is with '!' which is important to execute
    shell commands. Below will capture it properly."""
    temp_output_name = ""
    temp_error_name = ""
    temp_input_name = ""
    lines = ""

    def _safe_remove(path_name):
        try:
            if path_name != "" and os.path.exists(path_name):
                os.remove(path_name)
        except:
            pass

    try:
        tmp_output = tempfile.NamedTemporaryFile(delete=False, prefix="pycrashext-output-", suffix=".txt")
        tmp_error = tempfile.NamedTemporaryFile(delete=False, prefix="pycrashext-error-", suffix=".txt")
        temp_output_name = tmp_output.name
        temp_error_name = tmp_error.name
        tmp_output.close()
        tmp_error.close()

        command = command + " > " + shlex.quote(temp_output_name) + \
                " 2> " + shlex.quote(temp_error_name)
        if file_content != "":
            with tempfile.NamedTemporaryFile(delete=False, mode='w',
                                            prefix="pycrashext-input-", suffix=".txt") as fp:
                fp.write(file_content)
                temp_input_name = fp.name
            command = command + " < " + shlex.quote(temp_input_name)

        func(command)
        if os.path.exists(temp_output_name):
            with open(temp_output_name, 'r') as f:
                try:
                    lines = lines + "".join(f.readlines())
                except:
                    lines = "Failed to read " + temp_output_name

        if os.path.exists(temp_error_name):
            with open(temp_error_name, 'r') as f:
                try:
                    lines = lines + "".join(f.readlines())
                except:
                    lines = "Failed to read " + temp_error_name
    except Exception as e:
        lines = str(e)
    finally:
        for tmp_name in [temp_output_name, temp_error_name, temp_input_name]:
            _safe_remove(tmp_name)

    return lines


def run_command(func, command):
    return run_command_with_file(func, command, "")


def run_gdb_command(command):
    return run_command(exec_gdb_command, command)


def run_crash_command(command):
    return run_command(exec_crash_command, command)


def run_gdb_command_with_file(command, file_content):
    return run_command_with_file(exec_gdb_command, command, file_content)


def run_crash_command_with_file(command, file_content):
    return run_command_with_file(exec_crash_command, command, file_content)


def get_sizeof_struct(struct_name):
    result_size = 0
    try:
        output_lines = run_crash_command(struct_name).splitlines()
        if len(output_lines) == 0:
            return result_size
        result_str = output_lines[-1]
        size_str = result_str.split()[1]
        if size_str.startswith("0x"):
            result_size = int(size_str, 16)
        else:
            result_size = int(size_str)
    except Exception as e:
        print(e)
        pass

    return result_size


#
# Name resolution that does not go through getaddrinfo().
#
# crash runs PyKdump's bundled Python, which is statically linked. glibc's
# getaddrinfo() answers by dlopen()ing the NSS modules named in
# /etc/nsswitch.conf - libnss_files.so, libnss_dns.so - and a static
# interpreter cannot load them. Every name lookup then fails with
# 'Name or service not known' (EAI_NONAME, errno -2) inside crash while
# curl, ping and everything else on the same host resolve the name fine.
#
# The socket layer itself works, so the way out is to answer the question
# ourselves: read /etc/hosts, and failing that speak DNS directly to the
# nameservers in /etc/resolv.conf. Both paths only ever hand a numeric
# address to the socket layer, which never involves NSS.
#

DNS_PORT = 53
DNS_TIMEOUT = 3
DNS_TYPE_A = 1
DNS_CLASS_IN = 1


def is_numeric_host(hostname):
    """True if 'hostname' is already a literal address, so needs no lookup."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, hostname)
            return True
        except Exception:
            continue

    return False


def resolve_from_hosts_file(hostname, path="/etc/hosts"):
    """Address for 'hostname' out of /etc/hosts, or None if it is not there."""
    wanted = hostname.rstrip(".").lower()

    try:
        with open(path) as f:
            lines = f.readlines()
    except Exception:
        return None

    for line in lines:
        fields = line.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        for name in fields[1:]:
            if name.rstrip(".").lower() == wanted:
                return fields[0]

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
    hostile and answers None for anything it cannot make sense of rather
    than letting a malformed response raise into the caller.
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


def resolve_host(hostname, timeout=DNS_TIMEOUT):
    """Address for 'hostname' without calling getaddrinfo(), or None.

    Tries, in the order the C library would: a literal address as-is,
    /etc/hosts, then the nameservers from /etc/resolv.conf - first for the
    name as given, then qualified with each search domain.
    """
    if hostname is None or hostname == "":
        return None

    if is_numeric_host(hostname):
        return hostname

    address = resolve_from_hosts_file(hostname)
    if address is not None:
        return address

    servers = get_resolv_conf_nameservers()
    if len(servers) == 0:
        return None

    candidates = [hostname]
    if "." not in hostname.rstrip("."):
        for domain in get_resolv_conf_search():
            candidates.append("%s.%s" % (hostname.rstrip("."),
                                         domain.rstrip(".")))

    for candidate in candidates:
        for server in servers:
            address = query_dns_server(candidate, server, timeout)
            if address is not None:
                return address

    return None


def url_with_resolved_host(url):
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

    address = resolve_host(hostname)
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
    """True if a URLError reason is a name-lookup failure rather than a refusal.

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
    """POST 'encoded_data' to 'url', optionally overriding the Host: header."""
    req = urllib.request.Request(url, data=encoded_data, method='POST')
    if host_header is not None:
        # The URL now carries an address rather than a name, so the name has
        # to travel in the header instead, or a name-based virtual host on
        # the far end will serve the wrong site - or refuse outright.
        req.add_header('Host', host_header)

    if timeout is None:
        return urllib.request.urlopen(req)

    return urllib.request.urlopen(req, timeout=timeout)


def urlopen_post(url, encoded_data, timeout=None, verbose=False):
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

        resolved_url, host_header = url_with_resolved_host(url)
        if resolved_url is None:
            raise

        if verbose:
            print("Name lookup failed; retrying via %s" % resolved_url)

        try:
            return post_url(resolved_url, encoded_data, timeout, host_header)
        except Exception:
            pass

        # Report what the caller actually asked for, not the retry's failure
        raise e


def print_dns_failure_help(url, reason):
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
