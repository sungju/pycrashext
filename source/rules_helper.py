"""
Shared helpers for the autocheck detection rules under ./rules.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *

from LinuxDump import Tasks

import crashhelper
import meminfo


def get_data(basic_data, command):
    return exec_crash_command(command)


def get_symbol(symbol):
    return readSymbol(symbol)


def is_symbol_exists(symbol):
    return symbol_exists(symbol)


def get_size_str(size):
    return meminfo.get_size_str(size)


def get_page_size():
    return meminfo.get_page_size()


def get_page_shift():
    return meminfo.get_page_shift()


def get_slab_summary(name):
    """
    One 'kmem -s <cache>' row as a dict, or None when there is no such cache.

    Keys: objsize, allocated, total, slabs, ssize.

    Use the lowercase 'kmem -s': the uppercase '-S' additionally lists
    every object in the cache, which on a dentry or inode cache holding
    millions of them turns a rule into a several-minute wait.
    """
    try:
        output = exec_crash_command("kmem -s %s" % name)
    except Exception:
        return None

    for line in output.splitlines():
        words = line.split()
        if len(words) < 7 or words[-1] != name:
            continue
        try:
            return {
                "name":      name,
                "objsize":   int(words[1]),
                "allocated": int(words[2]),
                "total":     int(words[3]),
                "slabs":     int(words[4]),
                "ssize":     words[5],
            }
        except ValueError:
            continue

    return None


def get_total_memory_bytes():
    """Installed RAM in bytes, or 0 when it cannot be determined."""
    try:
        total_kb = meminfo.get_meminfo().get('MemTotal', 0)
        if total_kb > 0:
            return total_kb * 1024
    except Exception:
        pass

    for name in ("totalram_pages", "_totalram_pages"):
        try:
            if not symbol_exists(name):
                continue
            value = readSymbol(name)
            try:
                pages = int(value.counter)      # atomic_long_t, 5.0 onwards
            except Exception:
                pages = int(value)
            if pages > 0:
                return pages * get_page_size()
        except Exception:
            continue

    return 0
