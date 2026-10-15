"""
autocheck rule: detects the VFS caches eating the machine.

A dentry or inode slab cache large enough to matter rarely announces
itself - there is no oops and no hung task, just a machine that reclaims
badly or OOMs with most of its memory in slab. This rule puts a number on
it and hands over to 'fsinfo --icache', which can say which filesystem it
is and whether the objects are pinned or merely cached.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import sys
import ntpath

import rules_helper as rh


# Caches holding VFS objects. Asked for by name: 'kmem -s' with no
# argument walks every cache in the system, which is far too slow for a
# rule that runs as part of every autocheck.
VFS_CACHES = [
    "dentry",
    "inode_cache",
    "xfs_inode",
    "ext4_inode_cache",
    "ext3_inode_cache",
    "btrfs_inode",
    "nfs_inode_cache",
    "cifs_inode_cache",
    "fuse_inode",
    "overlay_inode",
    "shmem_inode_cache",
    "proc_inode_cache",
    "sock_inode_cache",
]

# Share of RAM in VFS object caches that stops being housekeeping and
# starts being the problem. The dcache and icache are meant to grow into
# free memory, so this has to be high enough not to fire on a healthy
# file server.
VFS_CACHE_PERCENT_THRESHOLD = 30

# Share of a cache's objects that are allocated but unused. Slabs are only
# returned when every object on them is free, so a cache that is mostly
# empty and still huge is fragmented - freeing more objects will not give
# the memory back.
FRAGMENTATION_PERCENT_THRESHOLD = 50


def is_major():
    return True


def description():
    return "Checking whether the dentry/inode caches are consuming memory"


def add_rule(sysinfo):
    # Nothing here is version-specific: it reads slab sizes, which every
    # kernel has.
    return True


def run_rule(basic_data):
    try:
        total_memory = rh.get_total_memory_bytes()
        if total_memory <= 0:
            return None

        caches = []
        vfs_bytes = 0
        for name in VFS_CACHES:
            summary = rh.get_slab_summary(name)
            if summary is None or summary["total"] <= 0:
                continue

            cache_bytes = summary["total"] * summary["objsize"]
            vfs_bytes = vfs_bytes + cache_bytes
            caches.append((cache_bytes, summary))

        if not caches:
            return None

        vfs_percent = vfs_bytes * 100.0 / total_memory
        if vfs_percent < VFS_CACHE_PERCENT_THRESHOLD:
            return None

        caches.sort(reverse=True, key=lambda entry: entry[0])

        lines = []
        lines.append("The VFS object caches hold %s of %s (%.1f%% of RAM)."
                     % (rh.get_size_str(vfs_bytes),
                        rh.get_size_str(total_memory), vfs_percent))
        lines.append("")
        lines.append("  %-20s %12s %12s %10s %8s" %
                     ("CACHE", "ALLOCATED", "TOTAL", "MEMORY", "%RAM"))
        for cache_bytes, summary in caches:
            lines.append("  %-20s %12d %12d %10s %7.1f%%" %
                         (summary["name"], summary["allocated"],
                          summary["total"], rh.get_size_str(cache_bytes),
                          cache_bytes * 100.0 / total_memory))

        biggest = caches[0][1]
        lines.append("")
        lines.append("Largest is '%s'." % biggest["name"])

        # Fragmentation changes the advice completely, so say it up front
        fragmented = []
        for _cache_bytes, summary in caches:
            unused = summary["total"] - summary["allocated"]
            if summary["total"] <= 0:
                continue
            percent = unused * 100.0 / summary["total"]
            if percent >= FRAGMENTATION_PERCENT_THRESHOLD:
                fragmented.append((summary["name"], percent))

        if fragmented:
            lines.append("")
            lines.append("These caches are mostly empty and still large,"
                         " i.e. fragmented:")
            for name, percent in fragmented:
                lines.append("  %-20s %.0f%% of its objects are free" %
                             (name, percent))
            lines.append("The memory is held by partly-used slabs, so"
                         " freeing further")
            lines.append("objects will not return it - only whole empty"
                         " slabs go back.")

        lines.append("")
        lines.append("Next steps:")
        lines.append("  fsinfo --icache"
                     "                 which filesystem holds them")
        lines.append("  fsinfo --icache <super_block>"
                     "   pinned vs reclaimable, and by whom")
        lines.append("")
        lines.append("Pinned objects cannot be reclaimed at any memory"
                     " pressure and mean")
        lines.append("something is holding references; reclaimable ones"
                     " mean reclaim")
        lines.append("itself is not running, and that is a different"
                     " investigation.")

        result_dict = {}
        result_dict["TITLE"] = "VFS cache bloat detected by %s" % \
                               ntpath.basename(__file__)
        result_dict["MSG"] = "\n".join(lines)

        return [result_dict]
    except Exception as e:
        print("Error running rule %s: %s" % (ntpath.basename(__file__), e))
        return None


def vfs_cache_bloat():
    import pprint
    pp = pprint.PrettyPrinter(indent=0, width=180)
    pp.pprint(run_rule(None))


if __name__ == '__main__':
    vfs_cache_bloat()
