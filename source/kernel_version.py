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
        A tuple (rhel_ver, major, minor, patch, release) of ints, or None
        if the string is not a recognizable RHEL kernel version.

        rhel_ver: RHEL major version (e.g. 9 for el9)
        major, minor, patch: Kernel version numbers
        release: Build release number (the numeric part before .elN)
    """
    if not ver_str or not isinstance(ver_str, str):
        return None

    # Match: major.minor.patch-release[.extra].elN[_minor][.arch]
    # Handles dotted release numbers like 425.3.1.el8 and minor variants like el9_5
    m = re.search(
        r'^(\d+)\.(\d+)\.(\d+)-(\d+)[.\d]*\.el(\d+)(?:_\d+)?',
        ver_str.strip()
    )
    if not m:
        return None

    major, minor, patch, release, rhel_ver = (int(x) for x in m.groups())
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
