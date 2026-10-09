"""
'kvercmp' command: is a fix already in this vmcore's kernel?

Compares the dump's kernel release with the fixed kernels an errata or KCS
article lists, using the same rules everywhere (kernel_version.fix_status):
only the same RHEL major counts, a fix in the kernel's own minor release is
compared in full (553.5.1 < 553.77.1), and a fix from an earlier minor
release only makes the kernel LIKELY_FIXED, to confirm with 'git log'.

Prints every version as parsed, then the verdict, and a last line
"KVERCMP verdict=<FIXED|LIKELY_FIXED|NOT_FIXED|NO_MATCH|UNKNOWN> ..." for
scripts. The same report runs outside crash:
    python3 kernel_version.py <kernel> <fixed kernel>...

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *

import kernel_version


def dump_release():
    """The RELEASE line of 'sys', or None."""
    for line in exec_crash_command("sys").splitlines():
        words = line.split()
        if len(words) >= 2 and words[0] == "RELEASE:":
            return words[1]
    return None


def kvercmp():
    op = OptionParser(usage="kvercmp [-k <kernel>] <fixed kernel>...")
    op.add_option("-k", "--kernel", dest="kernel", default=None,
                  help="Kernel to check instead of this dump's own release")

    (o, args) = op.parse_args()
    if not args:
        print("usage: kvercmp [-k <kernel>] <fixed kernel>...")
        print("  e.g. kvercmp kernel-4.18.0-425.3.1.el8 kernel-5.14.0-162.6.1.el9_1")
        return
    current = o.kernel or dump_release()
    if not current:
        print("Could not read the kernel release from 'sys'; give it with -k")
        return
    print(kernel_version.report(current, args)[1])


if ( __name__ == '__main__'):
    kvercmp()
