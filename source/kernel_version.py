"""
Helper for parsing and comparing kernel version strings.

An identical copy lives in pycrashext and in isos (source/kernel_version.py)
so that `kvercmp` gives the same verdict on a vmcore and on a sosreport:
change both together.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import re


def parse_kernel_version(ver_str):
    """
    Parse a kernel version string into its components.

    Args:
        ver_str: Kernel version string (e.g. "5.14.0-123.el9.x86_64")

    Returns:
        A tuple (rhel_ver, major, minor, patch, release), or None if the
        string is not a recognizable RHEL kernel version.

        rhel_ver: RHEL major version (e.g. 9 for el9)
        major, minor, patch: Kernel version numbers
        release: Tuple of ints for the full dotted build release before .elN,
                 e.g. (553, 146, 1) for 4.18.0-553.146.1.el8_10

    The release has to keep every component. RHEL ships its whole z-stream
    under one release number - 553.5.1, 553.40.1 and 553.159.1 are all 553 -
    so reducing it to that leading number makes every z-stream in a release
    compare equal, and any >= test between two of them answers True.
    """
    if not ver_str or not isinstance(ver_str, str):
        return None

    # Match: major.minor.patch-release[.release...].elN[_minor][.arch]
    # Handles dotted release numbers like 425.3.1.el8 and minor variants like el9_5
    m = re.search(
        r'^(\d+)\.(\d+)\.(\d+)-(\d+(?:\.\d+)*)\.el(\d+)(?:_\d+)?',
        ver_str.strip()
    )
    if not m:
        return None

    major, minor, patch = (int(m.group(i)) for i in (1, 2, 3))
    release = tuple(int(x) for x in m.group(4).split('.'))
    rhel_ver = int(m.group(5))
    return (rhel_ver, major, minor, patch, release)


def get_rhel_version(ver_str):
    """
    Extract the RHEL major version number from a kernel version string.

    Args:
        ver_str: Kernel version string (e.g. "5.14.0-123.el9.x86_64")

    Returns:
        Integer RHEL version (e.g. 9), or None if not a RHEL kernel.
    """
    parsed = parse_kernel_version(ver_str)
    if parsed is None:
        return None
    return parsed[0]


def is_rhel_kernel(ver_str):
    """
    Return True if ver_str is a recognizable RHEL kernel version string.

    Args:
        ver_str: Kernel version string to check.
    """
    return parse_kernel_version(ver_str) is not None


def kernel_version_ge(ver_a, ver_b):
    """
    Return True if kernel version ver_a is greater than or equal to ver_b.

    Comparison order: RHEL major version, then kernel major.minor.patch,
    then build release number.  Non-RHEL kernels are considered less than
    any RHEL kernel.  Two non-RHEL kernels are considered equal.

    Args:
        ver_a: Kernel version string (e.g. "5.14.0-123.el9.x86_64")
        ver_b: Kernel version string to compare against

    Returns:
        True if ver_a >= ver_b, False otherwise.
    """
    parsed_a = parse_kernel_version(ver_a)
    parsed_b = parse_kernel_version(ver_b)

    if parsed_a is None and parsed_b is None:
        return True   # both non-RHEL: treat as equal
    if parsed_a is None:
        return False  # non-RHEL < any RHEL
    if parsed_b is None:
        return True   # RHEL >= non-RHEL

    return parsed_a >= parsed_b


def normalize_kernel_version(ver_str):
    """
    Strip what an errata or KCS writes around a kernel version:
    "kernel-4.18.0-425.3.1.el8" and "kernel-rt-..." become
    "4.18.0-425.3.1.el8".
    """
    if not ver_str:
        return ver_str
    return re.sub(r'^kernel(-rt)?-', '', ver_str.strip())


# Verdicts of fix_status().  LIKELY_FIXED is a release-number inference only;
# confirm it with the kernel's git history before calling the fix applied.
FIXED = "FIXED"
LIKELY_FIXED = "LIKELY_FIXED"
NOT_FIXED = "NOT_FIXED"
NO_MATCH = "NO_MATCH"
UNKNOWN = "UNKNOWN"


def _stream(parsed):
    """The minor release a kernel belongs to: base version and release number."""
    return (parsed[1], parsed[2], parsed[3], parsed[4][0])


def fix_status(current, fixes):
    """
    Is a fix already in kernel `current`, given the fixed kernels an errata
    or KCS article lists (any RHEL majors, any minor releases)?

    Only fixes for the same RHEL major count. Then:
      - a fix in the same minor release (the same release number, e.g. 553
        for every 4.18.0-553.*.el8_10 build): FIXED when current is at or
        after it, else NOT_FIXED. This is the only exact answer;
      - otherwise a fix from an earlier minor release: LIKELY_FIXED, since a
        later release normally carries it. Confirm with git history;
      - otherwise every listed fix is in a later release: NOT_FIXED.

    Returns (verdict, fix, reason); fix is the version compared against, or
    None.
    """
    cur = parse_kernel_version(normalize_kernel_version(current))
    if cur is None:
        return (UNKNOWN, None, "'%s' is not a RHEL kernel version" % current)
    same = []
    for f in fixes:
        p = parse_kernel_version(normalize_kernel_version(f))
        if p is not None and p[0] == cur[0]:
            same.append((p, normalize_kernel_version(f)))
    if not same:
        return (NO_MATCH, None, "no fixed kernel is listed for RHEL %d" % cur[0])
    same.sort()
    in_stream = [x for x in same if _stream(x[0]) == _stream(cur)]
    if in_stream:
        p, f = in_stream[0]
        if cur >= p:
            return (FIXED, f, "same minor release (%d): the kernel is at or after the fix"
                    % cur[4][0])
        return (NOT_FIXED, f, "same minor release (%d): the kernel is older than the fix"
                % cur[4][0])
    earlier = [x for x in same if _stream(x[0]) < _stream(cur)]
    if earlier:
        p, f = earlier[-1]
        return (LIKELY_FIXED, f, "the kernel's release (%d) is later than the fix's (%d) and "
                "no fix is listed for its own release; confirm with git history"
                % (cur[4][0], p[4][0]))
    p, f = same[0]
    return (NOT_FIXED, f, "the kernel's release (%d) is earlier than every listed fix; "
            "the first is in release %d" % (cur[4][0], p[4][0]))


def describe(ver_str, cur=None):
    """One line naming a version's RHEL major and release, for reports."""
    p = parse_kernel_version(normalize_kernel_version(ver_str))
    if p is None:
        return "not a RHEL kernel version"
    text = "RHEL %d, release %s" % (p[0], ".".join(str(x) for x in p[4]))
    if cur is not None and cur != p:
        if p[0] != cur[0]:
            text += "; other RHEL major, not compared"
        elif _stream(p) == _stream(cur):
            text += "; same minor release"
        else:
            text += "; %s minor release" % ("earlier" if _stream(p) < _stream(cur) else "later")
    return text


def report(current, fixes):
    """The kvercmp report: every input as parsed, then the verdict."""
    cur = parse_kernel_version(normalize_kernel_version(current))
    lines = ["current  %-32s %s" % (normalize_kernel_version(current), describe(current))]
    for f in fixes:
        lines.append("fix      %-32s %s" % (normalize_kernel_version(f), describe(f, cur)))
    verdict, fix, reason = fix_status(current, fixes)
    lines.append("verdict  %s: %s" % (verdict, reason))
    lines.append("KVERCMP verdict=%s current=%s fix=%s"
                 % (verdict, normalize_kernel_version(current), fix or "-"))
    return verdict, "\n".join(lines)


if (__name__ == '__main__'):
    import sys
    if len(sys.argv) < 3:
        sys.stderr.write("usage: kernel_version.py <kernel> <fixed kernel>...\n")
        sys.exit(2)
    print(report(sys.argv[1], sys.argv[2:])[1])
