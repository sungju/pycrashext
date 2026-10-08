"""
Helper for parsing and comparing kernel version strings.

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
