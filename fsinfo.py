"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *
from LinuxDump import Tasks
import sys


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
        return -1

    try:
        crashout_list = exec_crash_command("mount")
        for mount_line in crashout_list.splitlines():
            mount_details = mount_line.split()
            if (mount_details[1] == ("%x" % sb)):
                return int(mount_details[0], 16)
    except:
        return -1

    return -1

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

        vfsmnt_addr = get_vfsmount_from_sb(sb)
        mnt_flags = 0
        if (vfsmnt_addr != -1):
            vfsmnt = readSU("struct vfsmount", vfsmnt_addr)
            mnt_flags = vfsmnt.mnt_flags

        print ("SB: 0x%14x, frozen=%s, %s (%s) [%s], (%s)" %
               (sb, frozen_str,
               dentry_to_filename(sb.s_root), sb.s_id,
                sb.s_type.name,
                get_mount_options(mnt_flags)))


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

def fsinfo():
    op = OptionParser()
    op.add_option("--details", dest="filesystem_details", default=0,
                  action="store_true",
                  help="Show detailed filesystem information")
    op.add_option("--findpidbyfile", dest="file_addr_for_pid", default="",
                  action="store",
                  help="Find PID from a /proc file address (hex)")
    op.add_option("--findpidbydentry", dest="dentry_addr_for_pid",
                  default="", action="store",
                  help="Find PID from a /proc dentry address (hex)")

    (o, args) = op.parse_args()

    if (o.file_addr_for_pid != ""):
        find_pid_from_file(o)
        sys.exit(0);
    if (o.dentry_addr_for_pid != ""):
        find_pid_from_dentry(o)
        sys.exit(0);

    all_filesystem_info(o)

if ( __name__ == '__main__'):
    fsinfo()
