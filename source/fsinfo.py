"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *
from LinuxDump import Tasks
import sys
import operator
import re

import crashcolor


def get_page_shift():
    resultline = exec_crash_command("ptob 1")
    if len(resultline) == 0:
        return 0

    words = resultline.split()
    if len(words) < 2:
        return 0

    value = int(words[1], 16)
    idx = 0
    while (value > 0):
        value = value >> 1
        idx = idx + 1

    return idx - 1


def dentry_to_filename (dentry) :
    if (dentry == 0):
        return "<>"

    try:
        crashout = exec_crash_command ("files -d {:#x}".format(dentry))
        filename = crashout.split()[-1]
        if filename == "DIR" :
            filename = "<blank>"
        return filename
    except:
        return "<invalid>"


def get_vfsmount_from_sb(sb):
    if (sb == 0):
        return None

    try:
        crashout_list = exec_crash_command("mount")
        for mount_line in crashout_list.splitlines():
            mount_details = mount_line.split()
            if (mount_details[1] == ("%x" % sb)):
                mount = readSU("struct mount", int(mount_details[0], 16))
                return mount.mnt
    except:
        return None

    return None 


def get_mount_option(mnt_flags):
    return {
        0x01: "nosuid",         # "MNT_NOSUID",
        0x02: "nodev",          # "MNT_NODEV",
        0x04: "noexec",         # "MNT_NOEXEC",
        0x08: "noatime",        # "MNT_NOATIME",
        0x10: "nodiratime",     # "MNT_NODIRATIME",
        0x20: "",               # "MNT_RELATIME",
        0x40: "ro",             # "MNT_READONLY",

# Below looks too much information, so, not visible for now
#        0x100: "SHRINKABLE",
#        0x200: "WRITE_HOLD",
#        0x1000: "SHARED",
#        0x2000: "UNBINDABLE",

        0x800000: "locked",     # MNT_LOCKED
        0x8000000: "umount",    # MNT_UMOUNT
    }.get(mnt_flags, "")

def get_mount_options(mnt_flags):
    result = ""
    for x in range(0, 64):
        option = get_mount_option((mnt_flags & (1 << x)))
        if (option != "" and result != ""):
            result = result + ","
        result = result + option

    return result

def get_frozen_str(frozen_type):
    return {
        0: "SB_UNFROZEN",
        1: "SB_FREEZE_WRITE",
        2: "SB_FREEZE_PAGEFAULT",
        3: "SB_FREEZE_FS",
        4: "SB_FREEZE_COMPLETE",
        -1: "UNRECOGNIZED STATE",
    }[frozen_type]


def all_filesystem_info(options):
    fs_state_list = {} 
    super_blocks = sym2addr("super_blocks")
    for sb in readSUListFromHead(super_blocks,
                                         "s_list",
                                         "struct super_block"):
        frozen = -1
        if (member_offset('struct super_block', 's_writers') >= 0):
            frozen = sb.s_writers.frozen
        elif (member_offset('struct super_block', 's_frozen') >= 0):
            frozen = sb.s_frozen

        frozen_str = get_frozen_str(frozen)
        fs_state_list[frozen_str] = fs_state_list[frozen_str] + 1 if frozen_str in fs_state_list else 1

        vfsmnt = get_vfsmount_from_sb(sb)
        mnt_flags = 0
        if (vfsmnt != None):
            mnt_flags = vfsmnt.mnt_flags


        if frozen_str == "SB_FREEZE_COMPLETE":
            crashcolor.set_color(crashcolor.LIGHTRED)
        elif frozen_str == "SB_FREEZE_WRITE":
            crashcolor.set_color(crashcolor.LIGHTCYAN)

        print ("SB: 0x%14x, frozen=%s, %s (%s) [%s], (%s)" %
               (sb, frozen_str,
               dentry_to_filename(sb.s_root), sb.s_id,
                sb.s_type.name,
                get_mount_options(mnt_flags)))
        crashcolor.set_color(crashcolor.RESET)

    print("")
    for frozen_str in fs_state_list:
        print("%25s = %d" % (frozen_str, fs_state_list[frozen_str]))


def find_pid_from_file(options):
    file_struct = readSU("struct file",
                         int(options.file_addr_for_pid, 16))
    d_inode = file_struct.f_path.dentry.d_inode;
    find_pid_from_inode(d_inode);


def find_pid_from_dentry(options):
    dentry = readSU("struct dentry",
                    int(options.dentry_addr_for_pid, 16))
    d_inode = dentry.d_inode;
    find_pid_from_inode(d_inode);


def find_pid_from_inode(d_inode):
    vfs_inode_offset = member_offset('struct proc_inode', 'vfs_inode');
    proc_inode = readSU("struct proc_inode", d_inode - vfs_inode_offset)
    pid_first = proc_inode.pid.tasks[0].first
    pids_offset = member_offset("struct task_struct", "pids");
    task_struct = readSU("struct task_struct", pid_first - pids_offset);

    crashout = exec_crash_command(
        "struct task_struct.pid,comm,files {:#x} -d".format(task_struct))
    print("struct task_struct.pid,comm,files %x\n%s" %
          (task_struct, crashout))

    return

O_RDONLY = 0x0
O_WRONLY = 0x1
O_RDWR = 0x2
O_ACCMODE = 0x3
O_CREATE = 0x40
O_EXCL = 0x80
O_NOCTTY = 0x100
O_TRUNC = 0x200
O_APPEND = 0x400
O_NONBLOCK = 0x800
O_DSYNC = 0x1000
FASYNC = 0x2000
O_DIRECT = 0x4000
O_LARGEFILE = 0x8000

def get_file_open_mode_str(f_mode):
    result_str = ""
    if ((f_mode & 0x03) == O_RDONLY):
        result_str = result_str + "Read-Only"
    if ((f_mode & 0x03) == O_WRONLY):
        result_str = result_str + "Write-Only"
    if ((f_mode & 0x03) == O_RDWR):
        result_str = result_str + "Read/Write"

    if ((f_mode & O_CREATE) == O_CREATE):
        result_str = result_str + ", O_CREATE"
    if ((f_mode & O_EXCL) == O_EXCL):
        result_str = result_str + ", O_EXCL"
    if ((f_mode & O_NOCTTY) == O_NOCTTY):
        result_str = result_str + ", O_NOCTTY"
    if ((f_mode & O_TRUNC) == O_TRUNC):
        result_str = result_str + ", O_TRUNC"
    if ((f_mode & O_APPEND) == O_APPEND):
        result_str = result_str + ", O_APPEND"
    if ((f_mode & O_NONBLOCK) == O_NONBLOCK):
        result_str = result_str + ", O_NONBLOCK"
    if ((f_mode & O_DSYNC) == O_DSYNC):
        result_str = result_str + ", O_DSYNC"
    if ((f_mode & FASYNC) == FASYNC):
        result_str = result_str + ", FASYNC"
    if ((f_mode & O_DIRECT) == O_DIRECT):
        result_str = result_str + ", O_DIRECT"
    if ((f_mode & O_LARGEFILE) == O_LARGEFILE):
        result_str = result_str + ", O_LARGEFILE"

    return result_str


def show_inode_details(options):
    inode = readSU("struct inode", int(options.inode, 16))
    dentry_offset = member_offset('struct dentry', 'd_u')
    if dentry_offset < 0:
        dentry_offset = member_offset('struct dentry',
                                      'd_alias')
    i_dentry_size = member_size("struct inode", "i_dentry")
    hlist_head_sz = struct_size("struct hlist_head")
    if i_dentry_size == hlist_head_sz:
        dentry_addr = inode.i_dentry.first - dentry_offset
    else:
        dentry_addr = inode.i_dentry.next - dentry_offset

    if dentry_addr != -dentry_offset: # No dentry for this inode
        dentry = readSU('struct dentry', dentry_addr)
        try:
            dentry_details = exec_crash_command("files -d 0x%x" % (dentry))
        except:
            dentry_details = ""
        print(dentry_details)
    elif inode.i_mapping != 0:
        i_mapping = inode.i_mapping
        print("inode = 0x%x, mapping = 0x%x, page flags = 0x%x" %
              (inode, i_mapping, i_mapping.flags))
        if inode.i_sb.s_bdi != 0:
            bdi = inode.i_sb.s_bdi
            try:
                dev_name = bdi.name
            except:
                dev_name = bdi.dev_name
            if dev_name != "" and bdi.dev != 0:
                dev_kobj_name = bdi.dev.kobj.name
            else:
                dev_kobj_name = ""

            print("\tbacking_dev_info 0x%x : %s %s" %
                  (bdi, dev_name, dev_kobj_name))
        print("")

    print("%s" % (get_inode_details(inode)))
    print("")


def size_to_human_readable(byte_size):
    result = "%d bytes" % (byte_size)
    conv_size = int(byte_size/1024/1024/1024) # GiB
    if conv_size > 0:
        return result + (" (%d GB)" % conv_size)

    conv_size = int(byte_size/1024/1024) # MiB
    if conv_size > 0:
        return result + (" (%d MB)" % conv_size)

    conv_size = int(byte_size/1024) # KiB
    if conv_size > 0:
        return result + (" (%d KB)" % conv_size)

    return result

def get_inode_details(inode):
    try:
        i_uid = inode.i_uid.val
        i_gid = inode.i_gid.val
    except:
        i_uid = inode.i_uid
        i_gid = inode.i_gid

    return "file size = %s, ino = %d, link count = %d\n\tuid = %d, gid = %d" %\
          (size_to_human_readable(inode.i_size), inode.i_ino, inode.i_nlink, i_uid, i_gid)


def show_file_details(options):
    file = readSU("struct file", int(options.file, 16))
    dentry_details = exec_crash_command("files -d 0x%x" % (file.f_path.dentry))
    print("== File Info ==")
    print(dentry_details)

    if " SOCK " in dentry_details:
        print("struct socket 0x%x" % file.private_data)

    f_op_sym = exec_crash_command("sym %x" % (file.f_op))
    print("file operations = %s" % (f_op_sym), end='')
    mount_details = exec_crash_command("mount").splitlines()
    mount_str = "%x" % (file.f_path.dentry.d_sb)
    print("file open mode = %s (0x%x)" % (get_file_open_mode_str(file.f_flags), file.f_flags))
    if member_offset("struct file", "f_inode") < 0:
        f_inode = file.f_path.dentry.d_inode
    else:
        f_inode = file.f_inode
    print("%s" % (get_inode_details(f_inode)))
    print("")
    found = False
    for mount_line in mount_details:
        words = mount_line.split()
        if words[1] == mount_str:
            if found == False:
                print("== Mount Info ==")
            print(mount_line)
            found = True



def show_open_file_size(options):
    all_files = exec_crash_command("foreach files").splitlines()
    for one_file in all_files:
        if one_file.find(" REG ") < 0:
            continue

        entries = one_file.split()
        options.file = entries[1]
        show_file_details(options)


def show_slab_dentry(options):
    try:
        result_lines = exec_crash_command("kmem -S dentry").splitlines()
        sb_dict = {}
        slab_coming = False
        for line in result_lines:
            words = line.split()
            if len(words) == 0:
                continue
            if words[0] == "SLAB":
                slab_coming = True
            elif slab_coming == True:
                slab_coming = False
                slab_lines = exec_crash_command("kmem -S 0x%s" % words[0])
                for slab_line in slab_lines.splitlines():
                    slab_line = slab_line.strip()
                    dentry_addr = 0
                    if slab_line.startswith("["):
                        dentry_addr = int(slab_line[1:-1], 16)

                    if dentry_addr > 0:
                        dentry = readSU("struct dentry", dentry_addr)
                        if dentry.d_sb not in sb_dict:
                            sb_dict[dentry.d_sb] = 0
                        sb_dict[dentry.d_sb] = sb_dict[dentry.d_sb] + 1
                        if options.show_details:
                            print("0x%x %s" % (dentry_addr, dentry_to_filename(dentry_addr)))

        print("\nsuberblock usage summary")
        print("=" * 30)
        print("%16s %8s %s" % ("super_block", "count", "root"))
        print("-" * 30)
        sorted_sb_dict = sorted(sb_dict.items(),
                                key=operator.itemgetter(1), reverse=True)
        total_count = 0
        for sb, count in sorted_sb_dict:
            try:
                print("0x%x %5d %s" %
                      (sb, count, dentry_to_filename(sb.s_root)))
            except:
                pass

            total_count = total_count + count
        print("-" * 40)
        print("Total allocated object count = %d" % (total_count))
        print("=" * 40)
    except Exception as e:
        print(e)
        pass


def show_caches(options):
    shrinker_list = readSymbol("shrinker_list")
    if shrinker_list == None or shrinker_list == 0:
        return

    sb_offset = member_offset("struct super_block", "s_shrink")
    if sb_offset < 0:
        return

    total_dentry_unused = 0
    total_inodes_unused = 0
    prune_super = sym2addr("prune_super")

    print("=" * 60)
    print("%18s %10s %10s %s" %\
          ("super_block", "dentries", "inodes", "path"))
    print("-" * 60)
    for shrinker in readSUListFromHead(shrinker_list,
                                       "list",
                                       "struct shrinker"):
        # Only concerns about normal super_block
        if shrinker.shrink != prune_super:
            continue

        sb = readSU("struct super_block", shrinker - sb_offset)
        dentry_unused = sb.s_nr_dentry_unused
        inodes_unused = sb.s_nr_inodes_unused
        if dentry_unused == 0 and inodes_unused == 0:
            continue
        total_dentry_unused = total_dentry_unused + dentry_unused
        total_inodes_unused = total_inodes_unused + inodes_unused

        print("0x%x %10d %10d %s" %\
              (sb, dentry_unused, inodes_unused,
               dentry_to_filename(sb.s_root)))

    print("-" * 60)
    print("%18s %10d %10d" %\
          ("Total", total_dentry_unused, total_inodes_unused))


def show_ext4_inode_cache_details(options, address):
    ext4_inode_info = readSU("struct ext4_inode_info", int(address, 16))
    options.inode = "%x" % ext4_inode_info.vfs_inode
    show_inode_details(options)


def show_ext4_inode_cache(options):
    try:
        slab_coming = False
        lines = exec_crash_command("kmem -S ext4_inode_cache")
        for line in lines.splitlines():
            words = line.split()
            if words[0] == "SLAB":
                slab_coming = True
            elif slab_coming == True:
                slab_coming = False
                slab_lines = exec_crash_command("kmem -S 0x%s" % words[0])
                for slab_line in slab_lines.splitlines():
                    slab_line = slab_line.strip()
                    if slab_line.startswith("["):
                        slab_line = slab_line[1:-1]
                        show_ext4_inode_cache_details(options, slab_line)
    except:
        pass


def show_cached_details(options):
    ext4_inode_cachep = readSymbol("ext4_inode_cachep")
    if ext4_inode_cachep != None and ext4_inode_cachep != 0:
        show_ext4_inode_cache(options)


I_FREEING = (1 << 5)
I_WILL_FREE = (1 << 4)
I_NEW = (1 << 3)
I_SKIP_STATE = I_FREEING | I_WILL_FREE | I_NEW

MS_BORN = (1 << 29)

page_caches = {}
wb_caches = {}


def pages_to_str(pages):
    page_bytes = pages * 4096
    result_str = ""
    if page_bytes > 1024*1024*1024:
        result_str = "%d GB" % (page_bytes/1024/1024/1024)
    elif page_bytes > 1024*1024:
        result_str = "%d MB" % (page_bytes/1024/1024)
    elif page_bytes > 1024:
        result_str = "%d KB" % (page_bytes/1024)
    else:
        result_str = "%d B" % (page_bytes)

    return result_str


#
# There's a little bit of differece between the calculated totla
# and the output of kmem -i (CACHED).
def show_page_caches(options):
    global page_caches
    global wb_caches
    page_caches = {}
    wb_caches = {}
    super_blocks = readSymbol("super_blocks")
    for sb in readSUListFromHead(super_blocks,
                                 "s_list",
                                 "struct super_block"):
        try:
            if sb.s_instances.pprev == 0:
                continue
        except:
            pass

        if sb.s_root != 0 and (sb.s_flags & MS_BORN) != 0:
            show_pagecache_sb(sb, options)


    sorted_sb_dict = sorted(page_caches.items(),
                            key=operator.itemgetter(1), reverse=True)
    total_count = 0
    exclude_count = 0
    print("=" * 79)
    print("%18s %9s %9s %-12s %-15s // %s" %\
          ("super_block   ", "pages ", "bytes  ", " s_id", "root", "wb"))
    print("-" * 79)
    for sb, count in sorted_sb_dict:
        try:
            total_count = total_count + count
            filename = dentry_to_filename(sb.s_root)
            if filename == "<blank>" or filename == "/dev/":
                exclude_count = exclude_count + count
                s_op_name = addr2sym(sb.s_op)
                if s_op_name == "shmem_ops":
                    filename = "shared memory"
            page_bytes = pages_to_str(count)
            wb_bytes = pages_to_str(wb_caches[sb])
            print("0x%x %9d (%7s) %-12s %-15s // %s" %
                  (sb, count, page_bytes, sb.s_id, filename, wb_bytes))
        except:
            pass

    print("-" * 79)
    print("Total number of page caches = %d (%s)" %
          (total_count, pages_to_str(total_count)))
    pages_without_dev = (total_count - exclude_count)
    print("   (exclude /dev/ and unnamed root) = %d (%s)" %
          (pages_without_dev, pages_to_str(pages_without_dev)))
    print("=" * 79)


FS_HAS_WBLIST=131072

def show_pagecache_sb(sb, options):
    global page_caches
    global wb_caches

    count = 0
    if (sb.s_type.fs_flags & FS_HAS_WBLIST) == FS_HAS_WBLIST:
        if addr2sym(sb.s_type) == "xfs_fs_type":
            for wb_node in readSUListFromHead(sb.s_inodes_wb,
                                            "next",
                                            "struct list_head",
                                            maxel=5000000):
                offset = member_offset("struct xfs_inode", "i_wblist")
                xfs_inode = readSU("struct xfs_inode", wb_node - offset)
                count = count + xfs_inode.i_vnode.i_mapping.nrpages

    wb_caches[sb] = count

    for inode in readSUListFromHead(sb.s_inodes,
                                    "i_sb_list",
                                    "struct inode",
                                   maxel=50000000):
        mapping = inode.i_mapping
        if mapping.nrpages == 0 or (inode.i_state & I_SKIP_STATE) != 0:
            continue

        if sb not in page_caches:
            page_caches[sb] = 0
        page_caches[sb] = page_caches[sb] + mapping.nrpages

        if options.show_details:
            options.inode = "%x" % inode
            print("-" * 10)
            print("CACHED_PAGES : %d" % (mapping.nrpages))
            show_inode_details(options)



BLOCK_SIZE_BITS = 10
BLOCKSIZE = 1 << BLOCK_SIZE_BITS

def get_uuid(s_uuid):
    result = "%0.2x%0.2x%0.2x%0.2x" % (s_uuid[0], s_uuid[1], s_uuid[2], s_uuid[3])
    result = ""
    for i in range(0, 4):
        result = result + "%0.2x" % (s_uuid[i])

    result = result + "-"
    for i in range(4, 6):
        result = result + "%0.2x" % (s_uuid[i])

    result = result + "-"
    for i in range(6, 8):
        result = result + "%0.2x" % (s_uuid[i])

    result = result + "-"
    for i in range(8, 16):
        result = result + "%0.2x" % (s_uuid[i])

    return result



def get_volume_name(s_volume_name):
    if s_volume_name.strip() == '':
        return "<none>"

    return s_volume_name


def get_attr_str(flags, flags_list, bitop=True):
    result = ""
    idx = 0
    if bitop:
        while flags > 0:
            key = 1 << idx
            if ((flags & 1) == 1) and (key in flags_list):
                result = result + flags_list[key] + " "
            idx = idx + 1
            flags = flags >> 1
    else:
        for key in flags_list:
            if (flags & key) == key:
                result = result + flags_list[key] + " "

    return result


def get_creator_os(creator_os):
    creator_os_list = {4: "lites",
                       3: "FreeBSD",
                       2: "Masix",
                       1: "Hurd",
                       0: "Linux"}
    result = get_attr_str(creator_os, creator_os_list, False)
    return result


def get_errors_behavior(s_errors):
    s_errors_list = {1: "Continue",
                     2: "Read-only",
                     3: "Panic"}
    result = get_attr_str(s_errors, s_errors_list, False)
    return result


def get_fs_state(s_state):
    fs_states_list = {0x0001: "clean",
                      0x0002: "error",
                      0x0004: "orphan"}
    result = get_attr_str(s_state, fs_states_list)
    return result


def get_default_mount_options(mount_options):
    mount_options_list = {0x00400: "journal_data",
                          0x02000: "no_uid32",
                          0x04000: "user_xattr",
                          0x08000: "acl"}
    result = get_attr_str(mount_options, mount_options_list)
    return result


def get_ext_flags(s_flags):
    s_flags_list = {0x0001: "signed_directory_hash",
                    0x0002: "unsigned_directory_hash",
                    0x0004: "test filesystem"}

    result = get_attr_str(s_flags, s_flags_list)
    return result


def get_extX_features(extX_super_block):
    s_feature_compat = extX_super_block.s_feature_compat
    s_feature_incompat = extX_super_block.s_feature_incompat
    s_feature_ro_compat = extX_super_block.s_feature_ro_compat

    compat_list = {0x0001: "dir_prealloc",
                   0x0002: "imagic_inodes",
                   0x0004: "has_journal",
                   0x0008: "ext_attr",
                   0x0010: "resize_inode",
                   0x0020: "dir_index",
                   0x0200: "sparse_super2"}

    ro_compat_list = {0x0001: "sparse_super",
                      0x0002: "large_file",
                      0x0004: "btree_dir",
                      0x0008: "huge_file",
                      0x0010: "uninit_bg", #"gdt_csum",
                      0x0020: "dir_nlink",
                      0x0040: "extra_isize",
                      0x0100: "quota",
                      0x0200: "bigalloc"}

    incompat_list = {0x0001: "compression",
                     0x0002: "filetype",
                     0x0004: "recover",
                     0x0008: "journal_dev",
                     0x0010: "meta_bg",
                     0x0040: "extents",
                     0x0080: "64bit",
                     0x0100: "mmp",
                     0x0200: "flex_bg",
                     0x0400: "ea_inode",
                     0x1000: "dirdata",
                     0x2000: "bg_use_meta_csum",
                     0x4000: "largedir",
                     0x8000: "inline_data"}

    result = get_attr_str(s_feature_compat, compat_list)
    result = result + get_attr_str(s_feature_incompat, incompat_list)
    result = result + get_attr_str(s_feature_ro_compat, ro_compat_list)

    return result


def show_extX_details(sb, fs_type):
    try:
        if fs_type == "ext4":
            extX_sb_info = readSU("struct ext4_sb_info", sb.s_fs_info)
            extX_super_block = readSU("struct ext4_super_block", extX_sb_info.s_es)

            s_blocks_count = (extX_super_block.s_blocks_count_hi << 32) +\
                            extX_super_block.s_blocks_count_lo
            s_r_blocks_count = (extX_super_block.s_r_blocks_count_hi << 32) +\
                            extX_super_block.s_r_blocks_count_lo
            s_free_blocks_count = (extX_super_block.s_free_blocks_count_hi << 32) +\
                            extX_super_block.s_free_blocks_count_lo
            s_frag_size = 0
        elif fs_type == "ext3":
            extX_sb_info = readSU("struct ext3_sb_info", sb.s_fs_info)
            extX_super_block = readSU("struct ext3_super_block", extX_sb_info.s_es)

            s_blocks_count = (extX_super_block.s_blocks_count_hi << 32) +\
                            extX_super_block.s_blocks_count
            s_r_blocks_count = (extX_super_block.s_r_blocks_count_hi << 32) +\
                            extX_super_block.s_r_blocks_count
            s_free_blocks_count = (extX_super_block.s_free_blocks_count_hi << 32) +\
                            extX_super_block.s_free_blocks_count
            s_frag_size = BLOCKSIZE << extX_super_block.s_log_frag_size
        elif fs_type == "ext2":
            extX_sb_info = readSU("struct ext2_sb_info", sb.s_fs_info)
            extX_super_block = readSU("struct ext2_super_block", extX_sb_info.s_es)

            s_blocks_count = (extX_super_block.s_blocks_count_hi << 32) +\
                            extX_super_block.s_blocks_count
            s_r_blocks_count = (extX_super_block.s_r_blocks_count_hi << 32) +\
                            extX_super_block.s_r_blocks_count
            s_free_blocks_count = (extX_super_block.s_free_blocks_count_hi << 32) +\
                            extX_super_block.s_free_blocks_count
            s_frag_size = BLOCKSIZE << extX_super_block.s_log_frag_size
        else:
            return

        s_block_size = BLOCKSIZE << extX_super_block.s_log_block_size

        print("< struct super_block 0x%x >" % sb)
        print("%-30s %s" % ("Filesystem volume name:", get_volume_name(extX_super_block.s_volume_name)))
        mnt_point = dentry_to_filename(sb.s_root)
        print("%-30s %s" % ("Last mounted on:", extX_super_block.s_last_mounted))
        print("%-30s %s" % ("Filesystem UUID:", get_uuid(extX_super_block.s_uuid)))
        print("%-30s 0x%X" % ("Filesystem magic number:", sb.s_magic))
        print("%-30s %d (%s)" % ("Filesystem revision #:", extX_super_block.s_rev_level, "dynamic" if extX_super_block.s_rev_level > 0 else "original"))
        print("%-30s %s" % ("Filesystem features:", get_extX_features(extX_super_block)))
        if fs_type != "ext2":
            print("%-30s %s" % ("Filesystem flags:", get_ext_flags(extX_super_block.s_flags)))

        print("%-30s %s" % ("Default mount options:", get_default_mount_options(extX_sb_info.s_mount_opt)))
        print("%-30s %s" % ("Filesystem state:", get_fs_state(extX_super_block.s_state)))
        print("%-30s %s" % ("Errors behavior:", get_errors_behavior(extX_super_block.s_errors)))
        print("%-30s %s" % ("Filesystem OS type:", get_creator_os(extX_super_block.s_creator_os)))
        print("%-30s %d" % ("Inode count:", extX_super_block.s_inodes_count))
        print("%-30s %d (%d KBytes)" % ("Block count:", s_blocks_count,
                                        (s_blocks_count * s_block_size) / 1024))
        print("%-30s %d (%d KBytes)" % ("Reserved block count:", s_r_blocks_count,
                                        (s_r_blocks_count * s_block_size) / 1024))
        print("%-30s %d (%d Kbytes)" % ("Free blocks:", s_free_blocks_count,
                                        (s_free_blocks_count * s_block_size) / 1024))
        print("%-30s %d" % ("Free inodes:", extX_super_block.s_free_inodes_count))
        print("%-30s %d" % ("First block:", extX_super_block.s_first_data_block))
        print("%-30s %d" % ("Block size:", s_block_size))
        print("%-30s %d" % ("Fragment size:", s_frag_size))
        if fs_type != "ext2":
            print("%-30s %d" % ("Reserved GDT blocks:", extX_super_block.s_reserved_gdt_blocks))
        # That's enough for now. The remaining will be implemented later if needed
        print("")
        print("# Available %d MBytes on %s" % ((s_free_blocks_count * s_block_size) / (1024 * 1024), mnt_point))
    except:
        print("Can't read details for 0x%x (%s)" % (sb, dentry_to_filename(sb.s_root)), end='')
        return


def show_xfs_details(sb, fs_type):
    xfs_mount = readSU("struct xfs_mount", sb.s_fs_info)
    xfs_sb = xfs_mount.m_sb
    if member_offset("struct xfs_mount", "m_fsname") >= 0:
        volume_name = get_volume_name(xfs_mount.m_fsname)
    else:
        volume_name = get_volume_name(xfs_sb.sb_fname)

    print("< struct super_block 0x%x >" % sb)
    print("%-30s %s" % ("Filesystem volume name", volume_name))
    mnt_point = dentry_to_filename(sb.s_root)
    print("%-30s %s" % ("Mount point", mnt_point))
    print("%-30s %x" % ("Magic number", xfs_sb.sb_magicnum))
    print("%-30s %d" % ("Block size", xfs_sb.sb_blocksize))
    print("%-30s %d" % ("Number of data blocks", xfs_sb.sb_dblocks))
    print("%-30s %d" % ("Number of realtime blocks", xfs_sb.sb_rblocks))

    print("%-30s %s" % ("UUID", get_uuid(xfs_sb.sb_uuid.b)))
    print("%-30s %d" % ("Size of an allocation group", xfs_sb.sb_agblocks))
    print("%-30s %d" % ("Number of allocation groups", xfs_sb.sb_agcount))
    print("%-30s %d" % ("Sector size(bytes)", xfs_sb.sb_sectsize))
    print("%-30s %d" % ("inode size(bytes)", xfs_sb.sb_inodesize))

    print("%-30s %d" % ("allocated inode count", xfs_sb.sb_icount))
    print("%-30s %d" % ("free inodes", xfs_sb.sb_ifree))
    print("%-30s %d" % ("free data blocks", xfs_sb.sb_fdblocks))
    print("%-30s %d" % ("free realtime extents", xfs_sb.sb_frextents))

    print("")
    print("# Available %d MBytes on %s" % ((xfs_sb.sb_blocksize * xfs_sb.sb_fdblocks) / (1024 * 1024), mnt_point))
    pass

def show_superblock(sb):
    fs_type = sb.s_type.name
    try:
        if fs_type == "ext4":
            show_extX_details(sb, fs_type)
            print()
        elif fs_type =="xfs":
            show_xfs_details(sb, fs_type)
            print()
    except Exception as e:
        print("Error in handling", sb)
        print(e)


def show_dumpe2fs(options):
    if options.dumpe2fs == "*":
        options.dumpe2fs = '.'

    super_blocks = sym2addr("super_blocks")
    printed = False
    for sb in readSUListFromHead(super_blocks,
                                "s_list",
                                "struct super_block"):
        mount_name = dentry_to_filename(sb.s_root)
        try:
            if re.search(options.dumpe2fs, mount_name):
                show_superblock(sb)
        except:
            if printed == False:
                print("Error occured. Please check your regular expression.")
                printed = True



def show_fsnotify_group(options):
    fsnotify_group = readSU("struct fsnotify_group",
                            int(options.fsnotify_group, 16))
    if member_offset("struct __wait_queue_head", "task_list") >= 0:
        notification_tasklist = fsnotify_group.notification_waitq.task_list
        field_name="task_list"
        wait_queue_name="struct __wait_queue"
    else:
        # RHEL8 uses different names for structure and entries
        notification_tasklist = fsnotify_group.notification_waitq.head
        field_name="entry"
        wait_queue_name="struct wait_queue_entry"

    for wq in readSUListFromHead(notification_tasklist,
                                 field_name,
                                 wait_queue_name):
        func = addr2sym(wq.func)
        print(wq)
        if func == "pollwake":
            pwq = readSU("struct poll_wqueues", wq.private)
            print("\tfunc: %s, task: %s <%s>" %
                  (func, pwq.polling_task, pwq.polling_task.comm))
        elif func == "woken_wake_function":
            tsk = readSU("struct task_struct", wq.private)
            print("\tfunc: %s, task: %s <%s>" %
                  (func, tsk, tsk.comm))
        elif func == "ep_poll_callback":
            print(func)
            epitem_offset = member_offset("struct eppoll_entry", "wait")
            eppoll_entry = readSU("struct eppoll_entry", wq - epitem_offset)
            epi = eppoll_entry.base
            ep = epi.ep
            print(epi)
            print(ep.wq)


    if options.show_details:
        if member_offset("struct fsnotify_group", "notification_list") >= 0:
            print("%s Notification List %s" % ("-"*20, "-"*20))
            inode_list = {}
            notification_list = fsnotify_group.notification_list
            for fsnotify_event in readSUListFromHead(notification_list,
                                                     "list",
                                                     "struct fsnotify_event"):
                inode_list[fsnotify_event.inode] = fsnotify_event

            for inode in inode_list:
                print(inode_list[inode])
                options.inode = "%x" % inode
                show_inode_details(options)

        print("%s Process with fsnofiy_group %s" % ("-"*20, "-"*20))
        tt = Tasks.TaskTable()
        for t in tt.allThreads():
            files_result = exec_crash_command("files %d" % t.pid)
            if files_result.find("[fanotify]") < 0:
                continue
            files_list = files_result.splitlines()
            for f in files_list:
                if f.find("[fanotify]") < 0:
                    continue
                words = f.split()
                file_data = readSU("struct file", int(words[1], 16))
                if file_data.private_data == fsnotify_group:
                    print("PID : %d (%s)" % (t.pid, t.comm))
                    print(f)

'''
        if member_offset("struct fsnotify_group", "fanotify_data") >= 0:
            print("%s Access wait List %s" % ("-"*20, "-"*20))
            access_waitq = fsnotify_group.fanotify_data.access_waitq
            cmd_str = "waitq 0x%x" % access_waitq
            print(cmd_str)
            print(exec_crash_command(cmd_str))
'''


DCACHE_ENTRY_TYPE=0x07000000
DCACHE_MISS_TYPE=0x00000000

def show_negative_dentries(options):
    result_lines = exec_crash_command("kmem -S dentry").splitlines()
    neg_cnt = 0
    total_cnt = 0
    for line in result_lines:
        words = line.split()
        if (len(words) == 0 or not words[0].startswith("[")):
            continue
        try:
            dentry = readSU("struct dentry", int(words[0][1:-1], 16))
            total_cnt = total_cnt + 1
            if (dentry.d_flags & DCACHE_ENTRY_TYPE) == DCACHE_MISS_TYPE:
                neg_cnt = neg_cnt + 1
                if options.show_details:
                    print("%s" % dentry_to_filename(dentry))
        except:
            continue

    print("Based on kmem -S dentry")
    print("Negative dentries : %d" % (neg_cnt))
    print("Total dentries    : %d" % (total_cnt))

    result_lines = exec_crash_command("p dentry_stat -d")
    print()
    print(result_lines)

def show_task_info(options):
    task_addr = int(options.task_info, 16)
    task_struct =readSU("struct task_struct", task_addr)
    print("0x%x : %s (%d)" % (task_struct, task_struct.comm, task_struct.pid))
    print("")
    options.file = "%x" % (task_struct.mm.exe_file)
    show_file_details(options)


PAGE_SIZE=0
_PAGE_FILE = 0x40


def init_swap_data():
    global PAGE_SIZE
    global _PAGE_FILE

    PAGE_SIZE = 1 << get_page_shift()
    arch = sys_info.machine
    if (arch in ("x86_64", "i386", "i686", "athlon")):
        _PAGE_FILE = 0x40
    if (sys_info.machine.startswith("arm")):
        _PAGE_FILE = (1 << 2)
    if (arch in ("aarch64")):
        _PAGE_FILE = (1 << 2)
    if (sys_info.machine.startswith("ppc")):
        pass
    if (sys_info.machine.startswith("s390")):
        _PAGE_FILE = 0x601


MM_SWAPENTS = 2

def show_task_swap_usage(task, options):
    swap_usage = 0
    mm_struct = task.mm
    if mm_struct == 0:
        return
    swap_usage = long(mm_struct.rss_stat.count[MM_SWAPENTS])
    if swap_usage > 0:
        print("%10d %15d %s" % (task.pid, swap_usage, task.comm))


def show_swap_usage(options):
    init_swap_data()
    init_task = readSymbol("init_task")
    print("%10s %15s %s" % ("PID", "SWAP", "COMM"))
    for task in readSUListFromHead(init_task.tasks,
                                   "tasks",
                                   "struct task_struct",
                                   maxel=5000000):
        show_task_swap_usage(task, options)


def fsinfo():
    op = OptionParser()
    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show detailed information")
    op.add_option("-c", "--caches", dest="show_caches", default=0,
                  action="store_true",
                  help="Show dentry/inodes caches")
    op.add_option("-C", "--CACHED", dest="show_cached_details", default=0,
                  action="store_true",
                  help="Show CACHED details")
    op.add_option("-f", "--file", dest="file", default="",
                  action="store",
                  help="Show detailed file information for 'struct file' address (hex)")
    op.add_option("--findpidbyfile", dest="file_addr_for_pid", default="",
                  action="store",
                  help="Find PID from a /proc file address (hex)")
    op.add_option("--findpidbydentry", dest="dentry_addr_for_pid",
                  default="", action="store",
                  help="Find PID from a /proc dentry address (hex)")
    op.add_option("-i", "--inode", dest="inode", default="",
                  action="store",
                  help="Show detailed inode information for 'struct inode' address (hex)")
    op.add_option("-n", "--fsnotify", dest="fsnotify_group", default="",
                  action="store",
                  help="Show fsnotify details for fsnotify_group")
    op.add_option("--negdents", dest="degative_dentries", default=0,
                  action="store_true",
                  help="Show negative dentries")
    op.add_option("-r", "--page_caches", dest="show_page_caches", default=0,
                  action="store_true",
                  help="Show page caches")
    op.add_option("-s", "--slab", dest="show_slab", default=0,
                  action="store_true",
                  help="Show all 'dentry' details in slab")
    op.add_option("--show_open_file_size", dest="show_open_file_size", default=0,
                  action="store_true",
                  help="Show file size of each open files")
    op.add_option("-S", "--swap", dest="show_swap", default=0,
                  action="store_true",
                  help="Show all 'dentry' details in slab")
    op.add_option("-t", "--task", dest="task_info", default="",
                  action="store",
                  help="Show task related information")
    op.add_option("-p", "--dumpe2fs", dest="dumpe2fs", default="",
                  action="store",
                  help="Shows dumpe2fs like information")

    (o, args) = op.parse_args()

    sys.setrecursionlimit(10**6)

    if (o.file_addr_for_pid != ""):
        find_pid_from_file(o)
        sys.exit(0);
    if (o.dentry_addr_for_pid != ""):
        find_pid_from_dentry(o)
        sys.exit(0);
    if (o.file != ""):
        show_file_details(o)
        sys.exit(0)
    if (o.inode != ""):
        show_inode_details(o)
        sys.exit(0)
    if (o.show_slab):
        show_slab_dentry(o)
        sys.exit(0)
    if (o.show_caches):
        show_caches(o)
        sys.exit(0)
    if (o.show_cached_details):
        show_cached_details(o)
        sys.exit(0)
    if (o.show_page_caches):
        show_page_caches(o)
        sys.exit(0)
    if (o.dumpe2fs != ""):
        show_dumpe2fs(o)
        sys.exit(0)

    if (o.fsnotify_group != ""):
        show_fsnotify_group(o)
        sys.exit(0)

    if (o.degative_dentries):
        show_negative_dentries(o)
        sys.exit(0)

    if (o.task_info):
        show_task_info(o)
        sys.exit(0)

    if (o.show_open_file_size):
        show_open_file_size(o)
        sys.exit(0)

    if (o.show_swap):
        show_swap_usage(o)
        sys.exit(0)


    all_filesystem_info(o)

if ( __name__ == '__main__'):
    fsinfo()
