"""
'auditinfo' command: kernel audit subsystem state (rules, backlog, status).

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *

import errno
import re
import time

import crashcolor

"""
#include/uapi/linux/audit.h

/* Rule fields */
                /* These are useful when checking the
                 * task structure at task creation time
                 * (AUDIT_PER_TASK).  */
"""
AUDIT_PID = 0
AUDIT_UID = 1
AUDIT_EUID = 2
AUDIT_SUID = 3
AUDIT_FSUID = 4
AUDIT_GID = 5
AUDIT_EGID = 6
AUDIT_SGID = 7
AUDIT_FSGID = 8
AUDIT_LOGINUID = 9
AUDIT_PERS = 10
AUDIT_ARCH = 11
AUDIT_MSGTYPE = 12
AUDIT_SUBJ_USER = 13
AUDIT_SUBJ_ROLE = 14
AUDIT_SUBJ_TYPE = 15
AUDIT_SUBJ_SEN = 16
AUDIT_SUBJ_CLR = 17
AUDIT_PPID = 18
AUDIT_OBJ_USER = 19
AUDIT_OBJ_ROLE = 20
AUDIT_OBJ_TYPE = 21
AUDIT_OBJ_LEV_LOW = 22
AUDIT_OBJ_LEV_HIGH = 23
AUDIT_LOGINUID_SET = 24
AUDIT_SESSIONID = 25
AUDIT_FSTYPE = 26


"""
                /* These are ONLY useful when checking
                 * at syscall exit time (AUDIT_AT_EXIT). */
"""
AUDIT_DEVMAJOR = 100
AUDIT_DEVMINOR = 101
AUDIT_INODE = 102
AUDIT_EXIT = 103
AUDIT_SUCCESS = 104
AUDIT_WATCH = 105
AUDIT_PERM = 106
AUDIT_DIR = 107
AUDIT_FILETYPE = 108
AUDIT_OBJ_UID = 109
AUDIT_OBJ_GID = 110
AUDIT_FIELD_COMPARE = 111
AUDIT_EXE = 112
AUDIT_SADDR_FAM = 113

AUDIT_ARG0 = 200
AUDIT_ARG1 = (AUDIT_ARG0+1)
AUDIT_ARG2 = (AUDIT_ARG0+2)
AUDIT_ARG3 = (AUDIT_ARG0+3)

AUDIT_FILTERKEY = 210

AUDIT_NEGATE = 0x80000000

audit_type_dict = {
    AUDIT_PID : "AUDIT_PID",
    AUDIT_UID : "AUDIT_UID",
    AUDIT_EUID : "AUDIT_EUID",
    AUDIT_SUID : "AUDIT_SUID",
    AUDIT_FSUID : "AUDIT_FSUID",
    AUDIT_GID : "AUDIT_GID",
    AUDIT_EGID : "AUDIT_EGID",
    AUDIT_SGID : "AUDIT_SGID",
    AUDIT_FSGID : "AUDIT_FSGID",
    AUDIT_LOGINUID : "AUDIT_LOGINUID",
    AUDIT_PERS : "AUDIT_PERS",
    AUDIT_ARCH : "AUDIT_ARCH",
    AUDIT_MSGTYPE : "AUDIT_MSGTYPE",
    AUDIT_SUBJ_USER : "AUDIT_SUBJ_USER",
    AUDIT_SUBJ_ROLE : "AUDIT_SUBJ_ROLE",
    AUDIT_SUBJ_TYPE : "AUDIT_SUBJ_TYPE",
    AUDIT_SUBJ_SEN : "AUDIT_SUBJ_SEN",
    AUDIT_SUBJ_CLR : "AUDIT_SUBJ_CLR",
    AUDIT_PPID : "AUDIT_PPID",
    AUDIT_OBJ_USER : "AUDIT_OBJ_USER",
    AUDIT_OBJ_ROLE : "AUDIT_OBJ_ROLE",
    AUDIT_OBJ_TYPE : "AUDIT_OBJ_TYPE",
    AUDIT_OBJ_LEV_LOW : "AUDIT_OBJ_LEV_LOW",
    AUDIT_OBJ_LEV_HIGH : "AUDIT_OBJ_LEV_HIGH",
    AUDIT_LOGINUID_SET : "AUDIT_LOGINUID_SET",
    AUDIT_SESSIONID : "AUDIT_SESSIONID",
    AUDIT_DEVMAJOR : "AUDIT_DEVMAJOR",
    AUDIT_DEVMINOR : "AUDIT_DEVMINOR",
    AUDIT_INODE : "AUDIT_INODE",
    AUDIT_EXIT : "AUDIT_EXIT",
    AUDIT_SUCCESS : "AUDIT_SUCCESS",
    AUDIT_WATCH : "AUDIT_WATCH",
    AUDIT_PERM : "AUDIT_PERM",
    AUDIT_DIR : "AUDIT_DIR",
    AUDIT_FILETYPE : "AUDIT_FILETYPE",
    AUDIT_OBJ_UID : "AUDIT_OBJ_UID",
    AUDIT_OBJ_GID : "AUDIT_OBJ_GID",
    AUDIT_FIELD_COMPARE : "AUDIT_FIELD_COMPARE",
    AUDIT_EXE : "AUDIT_EXE",
    AUDIT_ARG0 : "AUDIT_ARG0",
    AUDIT_ARG1 : "AUDIT_ARG1",
    AUDIT_ARG2 : "AUDIT_ARG2",
    AUDIT_ARG3 : "AUDIT_ARG3",
    AUDIT_FILTERKEY : "AUDIT_FILTERKEY",
    AUDIT_NEGATE : "AUDIT_NEGATE",
}


def get_audit_type_str(rule_type):
    if rule_type in audit_type_dict:
        return audit_type_dict[rule_type]

    return "%d" % rule_type



colored_type_list = [
    AUDIT_EXIT,
]

def set_color_for_particular_types(rule_type):
    if rule_type in colored_type_list:
        crashcolor.set_color(crashcolor.RED)


Audit_equal = 0
Audit_not_equal = 1
Audit_bitmask = 2
Audit_bittest = 3
Audit_lt = 4
Audit_gt = 5
Audit_le = 6
Audit_ge = 7
Audit_bad = 8

audit_ops = {
    Audit_equal : "=",
    Audit_not_equal : "!=",
    Audit_bitmask : "&",
    Audit_bittest : "&=",
    Audit_lt : "<",
    Audit_gt : ">",
    Audit_le : "<=",
    Audit_ge : ">=",
    Audit_bad : "?",
}


def get_audit_op_str(audit_op):
    if audit_op in audit_ops:
        return audit_ops[audit_op]

    return "%d" % audit_op



EM_NONE = 0
EM_M32 = 1
EM_SPARC = 2
EM_386 = 3
EM_68K = 4
EM_88K = 5
EM_486 = 6
EM_860 = 7
EM_MIPS = 8
EM_MIPS_RS3_LE = 10
EM_MIPS_RS4_BE = 10
EM_PARISC = 15
EM_SPARC32PLUS = 18
EM_PPC = 20
EM_PPC64 = 21
EM_SPU = 23
EM_ARM = 40
EM_SH = 42
EM_SPARCV9 = 43
EM_IA_64 = 50
EM_X86_64 = 62
EM_S390 = 22
EM_CRIS = 76
EM_V850 = 87
EM_M32R = 88
EM_H8_300 = 46
EM_MN10300 = 89
EM_OPENRISC = 92
EM_BLACKFIN = 106
EM_TI_C6000 = 140
EM_AARCH64  = 183
EM_MICROBLAZE = 189
EM_FRV = 0x5441
EM_AVR32 = 0x18ad
EM_ALPHA = 0x9026
EM_CYGNUS_V850 = 0x9080
EM_CYGNUS_M32R = 0x9041
EM_S390_OLD = 0xA390
EM_CYGNUS_MN10300 = 0xbeef


__AUDIT_ARCH_64BIT = 0x80000000
__AUDIT_ARCH_LE = 0x40000000
AUDIT_ARCH_AARCH64 = (EM_AARCH64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
AUDIT_ARCH_ALPHA = (EM_ALPHA|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
AUDIT_ARCH_ARM = (EM_ARM|__AUDIT_ARCH_LE)
AUDIT_ARCH_ARMEB = (EM_ARM)
AUDIT_ARCH_CRIS = (EM_CRIS|__AUDIT_ARCH_LE)
AUDIT_ARCH_FRV = (EM_FRV)
AUDIT_ARCH_H8300 = (EM_H8_300)
AUDIT_ARCH_I386 = (EM_386|__AUDIT_ARCH_LE)
AUDIT_ARCH_IA64 = (EM_IA_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
AUDIT_ARCH_M32R = (EM_M32R)
AUDIT_ARCH_M68K = (EM_68K)
AUDIT_ARCH_MICROBLAZE = (EM_MICROBLAZE)
AUDIT_ARCH_MIPS = (EM_MIPS)
AUDIT_ARCH_MIPSEL = (EM_MIPS|__AUDIT_ARCH_LE)
AUDIT_ARCH_MIPS64 = (EM_MIPS|__AUDIT_ARCH_64BIT)
AUDIT_ARCH_MIPSEL64 = (EM_MIPS|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
AUDIT_ARCH_OPENRISC = (EM_OPENRISC)
AUDIT_ARCH_PARISC = (EM_PARISC)
AUDIT_ARCH_PARISC64 = (EM_PARISC|__AUDIT_ARCH_64BIT)
AUDIT_ARCH_PPC = (EM_PPC)
AUDIT_ARCH_PPC64 = (EM_PPC64|__AUDIT_ARCH_64BIT)
AUDIT_ARCH_PPC64LE = (EM_PPC64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
AUDIT_ARCH_S390 = (EM_S390)
AUDIT_ARCH_S390X = (EM_S390|__AUDIT_ARCH_64BIT)
AUDIT_ARCH_SH = (EM_SH)
AUDIT_ARCH_SHEL = (EM_SH|__AUDIT_ARCH_LE)
AUDIT_ARCH_SH64 = (EM_SH|__AUDIT_ARCH_64BIT)
AUDIT_ARCH_SHEL64 = (EM_SH|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
AUDIT_ARCH_SPARC = (EM_SPARC)
AUDIT_ARCH_SPARC64 = (EM_SPARCV9|__AUDIT_ARCH_64BIT)
AUDIT_ARCH_X86_64 = (EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)


audit_arch_dict = {
    AUDIT_ARCH_ALPHA : "AUDIT_ARCH_ALPHA",
    AUDIT_ARCH_ARM : "arm",
    AUDIT_ARCH_AARCH64 : "arm64",
    AUDIT_ARCH_ARMEB : "AUDIT_ARCH_ARMEB",
    AUDIT_ARCH_CRIS : "AUDIT_ARCH_CRIS",
    AUDIT_ARCH_FRV : "AUDIT_ARCH_FRV",
    AUDIT_ARCH_H8300 : "AUDIT_ARCH_H8300",
    AUDIT_ARCH_I386 : "b32",
    AUDIT_ARCH_IA64 : "AUDIT_ARCH_IA64",
    AUDIT_ARCH_M32R : "AUDIT_ARCH_M32R",
    AUDIT_ARCH_M68K : "AUDIT_ARCH_M68K",
    AUDIT_ARCH_MICROBLAZE : "AUDIT_ARCH_MICROBLAZE",
    AUDIT_ARCH_MIPS : "mips",
    AUDIT_ARCH_MIPSEL : "AUDIT_ARCH_MIPSEL",
    AUDIT_ARCH_MIPS64 : "mips64",
    AUDIT_ARCH_MIPSEL64 : "AUDIT_ARCH_MIPSEL64",
    AUDIT_ARCH_OPENRISC : "AUDIT_ARCH_OPENRISC",
    AUDIT_ARCH_PARISC : "AUDIT_ARCH_PARISC",
    AUDIT_ARCH_PARISC64 : "AUDIT_ARCH_PARISC64",
    AUDIT_ARCH_PPC : "ppc",
    AUDIT_ARCH_PPC64 : "ppc64",
    AUDIT_ARCH_PPC64LE : "ppc64le",
    AUDIT_ARCH_S390 : "s390",
    AUDIT_ARCH_S390X : "s390x",
    AUDIT_ARCH_SH : "AUDIT_ARCH_SH",
    AUDIT_ARCH_SHEL : "AUDIT_ARCH_SHEL",
    AUDIT_ARCH_SH64 : "AUDIT_ARCH_SH64",
    AUDIT_ARCH_SHEL64 : "AUDIT_ARCH_SHEL64",
    AUDIT_ARCH_SPARC : "AUDIT_ARCH_SPARC",
    AUDIT_ARCH_SPARC64 : "AUDIT_ARCH_SPARC64",
    AUDIT_ARCH_X86_64 : "b64",
}

def get_audit_arch_str(arch_type):
    if arch_type in audit_arch_dict:
        return audit_arch_dict[arch_type]

    return "%d" % arch_type


# Filter lists (audit_krule.listnr). These are list numbers, not bits.
AUDIT_FILTER_PREPEND = 0x10
AUDIT_FILTER_USER   = 0x00    # Apply rule to user-generated messages
AUDIT_FILTER_TASK   = 0x01    # Apply rule at task creation (not syscall)
AUDIT_FILTER_ENTRY  = 0x02    # Apply rule at syscall entry
AUDIT_FILTER_WATCH  = 0x03    # Apply rule to file system watches
AUDIT_FILTER_EXIT   = 0x04    # Apply rule at syscall exit
AUDIT_FILTER_EXCLUDE = 0x05   # Apply rule before record creation
AUDIT_FILTER_TYPE   = AUDIT_FILTER_EXCLUDE
AUDIT_FILTER_FS     = 0x06    # Apply rule at __audit_inode_child
AUDIT_FILTER_URING_EXIT = 0x07  # Apply rule at io_uring op exit


# Names auditctl uses in '-a action,list'
audit_list_dict = {
    AUDIT_FILTER_USER : "user",
    AUDIT_FILTER_TASK : "task",
    AUDIT_FILTER_ENTRY : "entry",
    AUDIT_FILTER_WATCH : "watch",
    AUDIT_FILTER_EXIT : "exit",
    AUDIT_FILTER_EXCLUDE : "exclude",
    AUDIT_FILTER_FS : "filesystem",
    AUDIT_FILTER_URING_EXIT : "io_uring",
}


def get_audit_list_str(listnr):
    if listnr in audit_list_dict:
        return audit_list_dict[listnr]

    return "%d" % listnr


# Rule actions
AUDIT_NEVER    = 0    # Do not build context if rule matches
AUDIT_POSSIBLE = 1    # Build context if rule matches
AUDIT_ALWAYS   = 2    # Generate audit record if rule matches


audit_action_dict = {
    AUDIT_NEVER : "never",
    AUDIT_POSSIBLE : "possible",
    AUDIT_ALWAYS : "always",
}


def get_audit_action_str(action):
    if action in audit_action_dict:
        return audit_action_dict[action]

    return  "%d" % action


AUDIT_PERM_EXEC  = 1
AUDIT_PERM_WRITE = 2
AUDIT_PERM_READ  = 4
AUDIT_PERM_ATTR  = 8

# Same letters and order as auditctl
audit_perm_list = [
    (AUDIT_PERM_READ, "r"),
    (AUDIT_PERM_WRITE, "w"),
    (AUDIT_PERM_EXEC, "x"),
    (AUDIT_PERM_ATTR, "a"),
]


def get_audit_perm_str(val):
    result = ""
    for key, letter in audit_perm_list:
        if val & key:
            result = result + letter

    if result ==  "":
        result = "%d" % val

    return result


# Field names as auditctl prints them in '-F name<op>value'
audit_field_name_dict = {
    AUDIT_PID : "pid",
    AUDIT_UID : "uid",
    AUDIT_EUID : "euid",
    AUDIT_SUID : "suid",
    AUDIT_FSUID : "fsuid",
    AUDIT_GID : "gid",
    AUDIT_EGID : "egid",
    AUDIT_SGID : "sgid",
    AUDIT_FSGID : "fsgid",
    AUDIT_LOGINUID : "auid",
    AUDIT_PERS : "pers",
    AUDIT_ARCH : "arch",
    AUDIT_MSGTYPE : "msgtype",
    AUDIT_SUBJ_USER : "subj_user",
    AUDIT_SUBJ_ROLE : "subj_role",
    AUDIT_SUBJ_TYPE : "subj_type",
    AUDIT_SUBJ_SEN : "subj_sen",
    AUDIT_SUBJ_CLR : "subj_clr",
    AUDIT_PPID : "ppid",
    AUDIT_OBJ_USER : "obj_user",
    AUDIT_OBJ_ROLE : "obj_role",
    AUDIT_OBJ_TYPE : "obj_type",
    AUDIT_OBJ_LEV_LOW : "obj_lev_low",
    AUDIT_OBJ_LEV_HIGH : "obj_lev_high",
    AUDIT_LOGINUID_SET : "loginuid_set",
    AUDIT_SESSIONID : "sessionid",
    AUDIT_FSTYPE : "fstype",
    AUDIT_DEVMAJOR : "devmajor",
    AUDIT_DEVMINOR : "devminor",
    AUDIT_INODE : "inode",
    AUDIT_EXIT : "exit",
    AUDIT_SUCCESS : "success",
    AUDIT_WATCH : "path",
    AUDIT_PERM : "perm",
    AUDIT_DIR : "dir",
    AUDIT_FILETYPE : "filetype",
    AUDIT_OBJ_UID : "obj_uid",
    AUDIT_OBJ_GID : "obj_gid",
    AUDIT_FIELD_COMPARE : "field_compare",
    AUDIT_EXE : "exe",
    AUDIT_SADDR_FAM : "saddr_fam",
    AUDIT_ARG0 : "a0",
    AUDIT_ARG1 : "a1",
    AUDIT_ARG2 : "a2",
    AUDIT_ARG3 : "a3",
    AUDIT_FILTERKEY : "key",
}

audit_id_fields = [
    AUDIT_UID, AUDIT_EUID, AUDIT_SUID, AUDIT_FSUID, AUDIT_LOGINUID,
    AUDIT_OBJ_UID,
    AUDIT_GID, AUDIT_EGID, AUDIT_SGID, AUDIT_FSGID, AUDIT_OBJ_GID,
]

# Fields whose value is a string in audit_field.lsm_str
audit_lsm_fields = [
    AUDIT_SUBJ_USER, AUDIT_SUBJ_ROLE, AUDIT_SUBJ_TYPE,
    AUDIT_SUBJ_SEN, AUDIT_SUBJ_CLR,
    AUDIT_OBJ_USER, AUDIT_OBJ_ROLE, AUDIT_OBJ_TYPE,
    AUDIT_OBJ_LEV_LOW, AUDIT_OBJ_LEV_HIGH,
]

AUDIT_UID_UNSET = 0xffffffff
AUDIT_LOGINUID_LEGACY = 0x1   # audit_krule.pflags
AUDIT_KEY_SEPARATOR = '\x01'

audit_filetype_dict = {
    0o140000 : "socket",
    0o120000 : "link",
    0o100000 : "file",
    0o060000 : "block",
    0o040000 : "dir",
    0o020000 : "character",
    0o010000 : "fifo",
}

# Message types defined by the kernel (include/uapi/linux/audit.h)
audit_msgtype_dict = {
    1300 : "SYSCALL",
    1301 : "FS_WATCH",
    1302 : "PATH",
    1303 : "IPC",
    1304 : "SOCKETCALL",
    1305 : "CONFIG_CHANGE",
    1306 : "SOCKADDR",
    1307 : "CWD",
    1309 : "EXECVE",
    1311 : "IPC_SET_PERM",
    1312 : "MQ_OPEN",
    1313 : "MQ_SENDRECV",
    1314 : "MQ_NOTIFY",
    1315 : "MQ_GETSETATTR",
    1316 : "KERNEL_OTHER",
    1317 : "FD_PAIR",
    1318 : "OBJ_PID",
    1319 : "TTY",
    1320 : "EOE",
    1321 : "BPRM_FCAPS",
    1322 : "CAPSET",
    1323 : "MMAP",
    1324 : "NETFILTER_PKT",
    1325 : "NETFILTER_CFG",
    1326 : "SECCOMP",
    1327 : "PROCTITLE",
    1328 : "FEATURE_CHANGE",
    1329 : "REPLACE",
    1330 : "KERN_MODULE",
    1331 : "FANOTIFY",
    1332 : "TIME_INJOFFSET",
    1333 : "TIME_ADJNTPVAL",
    1334 : "BPF",
    1335 : "EVENT_LISTENER",
    1336 : "URINGOP",
    1337 : "OPENAT2",
    1400 : "AVC",
    1401 : "SELINUX_ERR",
    1402 : "AVC_PATH",
    1403 : "MAC_POLICY_LOAD",
    1404 : "MAC_STATUS",
    1405 : "MAC_CONFIG_CHANGE",
    1700 : "ANOM_PROMISCUOUS",
    1701 : "ANOM_ABEND",
    1702 : "ANOM_LINK",
    1703 : "ANOM_CREAT",
}

# AUDIT_COMPARE_* : (left, right) as auditctl prints them in '-C'
audit_compare_dict = {
    1 : ("uid", "obj_uid"),
    2 : ("gid", "obj_gid"),
    3 : ("euid", "obj_uid"),
    4 : ("egid", "obj_gid"),
    5 : ("auid", "obj_uid"),
    6 : ("suid", "obj_uid"),
    7 : ("sgid", "obj_gid"),
    8 : ("fsuid", "obj_uid"),
    9 : ("fsgid", "obj_gid"),
    10 : ("uid", "auid"),
    11 : ("uid", "euid"),
    12 : ("uid", "fsuid"),
    13 : ("uid", "suid"),
    14 : ("auid", "fsuid"),
    15 : ("auid", "suid"),
    16 : ("auid", "euid"),
    17 : ("euid", "suid"),
    18 : ("euid", "fsuid"),
    19 : ("suid", "fsuid"),
    20 : ("gid", "egid"),
    21 : ("gid", "fsgid"),
    22 : ("gid", "sgid"),
    23 : ("egid", "fsgid"),
    24 : ("egid", "sgid"),
    25 : ("sgid", "fsgid"),
}


# Colors used for audit rules and times. Empty when not on a terminal.
RULE_ACTION_COLORS = {
    AUDIT_ALWAYS : crashcolor.GREEN,
    AUDIT_NEVER : crashcolor.LIGHTRED,
}
RULE_LIST_COLOR = crashcolor.LIGHTBLUE
RULE_ARCH_COLOR = crashcolor.MAGENTA
RULE_SYSCALL_COLOR = crashcolor.YELLOW
RULE_VALUE_COLOR = crashcolor.CYAN
RULE_PATH_COLOR = crashcolor.LIGHTCYAN
RULE_PERM_COLOR = crashcolor.YELLOW
RULE_KEY_COLOR = crashcolor.LIGHTGREEN
TIME_COLOR = crashcolor.LIGHTCYAN
AGE_COLOR = crashcolor.YELLOW


def colored(text, color):
    color_str = crashcolor.get_color(color)
    if color_str == "":
        return text

    return color_str + text + crashcolor.get_color(crashcolor.RESET)


def to_s32(val):
    val = int(val) & 0xffffffff
    if val & 0x80000000:
        return val - 0x100000000

    return val


def read_string(addr, delimiter=0x0, highchar=128):
    result = ""
    idx = 0
    while True:
        one_byte = readU8(addr + idx)
        idx = idx + 1
        if one_byte == delimiter or one_byte > highchar:
            break
        result = result + str(chr(one_byte))

    return result


def get_audit_watch_path(rule):
    if not rule.watch:
        return ""

    return str(rule.watch.path)


def get_audit_dir_str(rule):
    if not rule.tree:
        return ""

    # 'pathname' is a flexible array at the end of struct audit_tree
    return read_string(int(rule.tree) +
                       member_offset("struct audit_tree", "pathname"))


def get_audit_exe_path(rule):
    try:
        if rule.exe:
            return str(rule.exe.path)
    except:
        pass

    return ""


def get_audit_keys(rule):
    filterkey = rule.filterkey
    if not filterkey:
        return []

    return [key for key in str(filterkey).split(AUDIT_KEY_SEPARATOR) if key]


def get_audit_id_str(fval):
    if fval == AUDIT_UID_UNSET:
        return "unset"

    return "%d" % fval


def get_audit_exit_str(fval):
    sval = to_s32(fval)
    if sval < 0 and -sval in errno.errorcode:
        return "-%s" % errno.errorcode[-sval]

    return "%d" % sval


def get_audit_field_str(rule, field):
    ftype = field.type
    fop = field.op
    op_str = get_audit_op_str(fop)
    fval = int(field.val) & 0xffffffff
    name = audit_field_name_dict.get(ftype, "%d" % ftype)

    if ftype == AUDIT_LOGINUID_SET and fval == 0:
        # 'auid=-1' is stored as 'loginuid_set=0' with a legacy flag
        try:
            if rule.pflags & AUDIT_LOGINUID_LEGACY:
                return "-F auid%s%s" % (op_str, colored("unset", RULE_VALUE_COLOR))
        except:
            pass

    if ftype == AUDIT_FIELD_COMPARE:
        if fval in audit_compare_dict:
            left, right = audit_compare_dict[fval]
            return "-C %s" % colored(left + op_str + right, RULE_VALUE_COLOR)
        return "-F %s%s%s" % (name, op_str, colored("%d" % fval, RULE_VALUE_COLOR))

    if ftype == AUDIT_ARCH:
        val_str = get_audit_arch_str(fval)
    elif ftype == AUDIT_PERM:
        val_str = get_audit_perm_str(fval)
    elif ftype == AUDIT_WATCH:
        val_str = get_audit_watch_path(rule)
    elif ftype == AUDIT_DIR:
        val_str = get_audit_dir_str(rule)
    elif ftype == AUDIT_EXE:
        val_str = get_audit_exe_path(rule)
    elif ftype in audit_lsm_fields:
        val_str = str(field.lsm_str) if field.lsm_str else ""
    elif ftype in audit_id_fields:
        val_str = get_audit_id_str(fval)
    elif ftype == AUDIT_EXIT:
        val_str = get_audit_exit_str(fval)
    elif ftype in (AUDIT_PID, AUDIT_PPID):
        val_str = "%d" % to_s32(fval)
    elif ftype == AUDIT_MSGTYPE:
        val_str = audit_msgtype_dict.get(fval, "%d" % fval)
    elif ftype == AUDIT_FILETYPE:
        val_str = audit_filetype_dict.get(fval, "%d" % fval)
    elif ftype >= AUDIT_ARG0 and ftype <= AUDIT_ARG3:
        if fop in (Audit_bitmask, Audit_bittest):
            val_str = "0x%x" % fval
        elif fval == 0xffffffff:
            val_str = "-1"
        else:
            val_str = "%d" % fval
    else:
        val_str = "%d" % fval

    if ftype == AUDIT_ARCH:
        val_color = RULE_ARCH_COLOR
    elif ftype in (AUDIT_WATCH, AUDIT_DIR, AUDIT_EXE):
        val_color = RULE_PATH_COLOR
    elif ftype == AUDIT_PERM:
        val_color = RULE_PERM_COLOR
    else:
        val_color = RULE_VALUE_COLOR

    return "-F %s%s%s" % (name, op_str, colored(val_str, val_color))


# Prefixes of syscall handler symbols in sys_call_table, longest first
syscall_sym_prefixes = (
    "__ia32_compat_sys_", "__x64_compat_sys_", "__x32_compat_sys_",
    "__arm64_compat_sys_", "__s390_compat_sys_", "__se_compat_sys_",
    "__x64_sys_", "__ia32_sys_", "__arm64_sys_", "__s390x_sys_",
    "__s390_sys_", "__se_sys_", "compat_sys_", "ptregs_", "stub_",
    "SyS_", "sys_",
)

syscall_table_cache = {}


def get_syscall_table_addr(arch_val):
    # A 32-bit arch on a 64-bit kernel goes through the compat table
    if arch_val is not None and not (arch_val & __AUDIT_ARCH_64BIT) and \
       sys_info.pointersize == 8:
        table_names = ["ia32_sys_call_table", "compat_sys_call_table"]
    else:
        table_names = ["sys_call_table"]

    for table_name in table_names:
        if table_name not in syscall_table_cache:
            try:
                syscall_table_cache[table_name] = sym2addr(table_name)
            except:
                syscall_table_cache[table_name] = 0
        if syscall_table_cache[table_name]:
            return syscall_table_cache[table_name]

    return 0


def get_syscall_name(table_addr, nr):
    try:
        name = addr2sym(readPtr(table_addr + nr * sys_info.pointersize))
    except:
        return None
    if not name:
        return None

    stripped = False
    found = True
    while found:
        found = False
        for prefix in syscall_sym_prefixes:
            if name.startswith(prefix):
                name = name[len(prefix):]
                stripped = found = True
                break

    # Anything else is not a syscall handler, e.g. beyond the table end
    if not stripped or name in ("", "ni_syscall"):
        return None

    return name


def is_all_syscalls(rule):
    # auditctl ignores the last mask word when checking for 'all'
    masks = [int(mask) & 0xffffffff for mask in rule.mask]
    for mask in masks[:-1]:
        if mask != 0xffffffff:
            return False

    return True


def takes_syscalls(rule):
    return rule.listnr not in (AUDIT_FILTER_USER, AUDIT_FILTER_TASK,
                               AUDIT_FILTER_EXCLUDE, AUDIT_FILTER_FS)


def get_mask_str(rule, arch_val, show_numbers=False):
    if not takes_syscalls(rule):
        return ""
    if is_all_syscalls(rule):
        return "-S %s" % colored("all", RULE_SYSCALL_COLOR)

    table_addr = get_syscall_table_addr(arch_val)
    syscalls = []
    for index, value in enumerate(rule.mask):
        for bit in range(32):
            if value & (1 << bit):
                syscall_number = index * 32 + bit
                name = None
                if table_addr:
                    name = get_syscall_name(table_addr, syscall_number)
                if name is None:
                    syscalls.append("%d" % syscall_number)
                elif show_numbers:
                    syscalls.append("%s(%d)" % (name, syscall_number))
                else:
                    syscalls.append(name)

    if len(syscalls) == 0:
        return ""

    return "-S " + colored(",".join(syscalls), RULE_SYSCALL_COLOR)


def is_watch_rule(rule, fields):
    """Same test auditctl uses to print a rule in '-w path -p perm' form"""
    has_perm = False
    for field in fields:
        if field.type == AUDIT_PERM:
            has_perm = True
        elif field.type not in (AUDIT_FILTERKEY, AUDIT_DIR, AUDIT_WATCH):
            return False

    if takes_syscalls(rule) and not is_all_syscalls(rule):
        return False

    return has_perm


def get_audit_rule_str(rule, options):
    fields = [rule.fields[i] for i in range(rule.field_count)]
    keys = get_audit_keys(rule)
    result = []

    if is_watch_rule(rule, fields):
        for field in fields:
            if field.type == AUDIT_WATCH:
                result.append("-w %s" % colored(get_audit_watch_path(rule), RULE_PATH_COLOR))
            elif field.type == AUDIT_DIR:
                result.append("-w %s" % colored(get_audit_dir_str(rule), RULE_PATH_COLOR))
        for field in fields:
            if field.type == AUDIT_PERM:
                result.append("-p %s" % colored(get_audit_perm_str(field.val), RULE_PERM_COLOR))
        for key in keys:
            result.append("-k %s" % colored(key, RULE_KEY_COLOR))

        return " ".join(result)

    action_color = RULE_ACTION_COLORS.get(rule.action, crashcolor.YELLOW)
    result.append("-a %s,%s" % (
        colored(get_audit_action_str(rule.action), action_color),
        colored(get_audit_list_str(rule.listnr), RULE_LIST_COLOR)))
    # auditctl prints arch first as it decides the syscall names
    arch_val = None
    for field in fields:
        if field.type == AUDIT_ARCH:
            arch_val = int(field.val) & 0xffffffff
            result.append(get_audit_field_str(rule, field))

    mask_str = get_mask_str(rule, arch_val, options.show_details)
    if mask_str != "":
        result.append(mask_str)

    for field in fields:
        if field.type == AUDIT_ARCH:
            continue
        if field.type == AUDIT_FILTERKEY:
            for key in keys:
                result.append("-F key=%s" % colored(key, RULE_KEY_COLOR))
            continue
        result.append(get_audit_field_str(rule, field))

    return " ".join(result)


def show_audit_rules(options):
    audit_rules_list = readSymbol("audit_rules_list")
    offset = member_offset("struct audit_entry", "rule")
    offset = offset + member_offset("struct audit_krule", "list")

    rule_count = 0
    for audit_rules in audit_rules_list:
        seen = set()
        next_addr = audit_rules.next
        while next_addr != audit_rules:
            # Don't spin forever on a corrupted list in a vmcore
            if not next_addr or int(next_addr) in seen:
                print("WARNING: audit_rules_list is corrupted at 0x%x" %
                      (int(next_addr)))
                break
            seen.add(int(next_addr))

            audit_entry = readSU("struct audit_entry", next_addr - offset)
            try:
                result_str = get_audit_rule_str(audit_entry.rule, options)
            except Exception as e:
                result_str = "<failed to read rule: %s>" % (e)

            if options.show_details:
                print("struct audit_entry 0x%x\n\t" % (audit_entry), end="")
            print("%s" % (result_str))
            rule_count = rule_count + 1
            next_addr = audit_entry.rule.list.next

    if rule_count == 0:
        print("No rules")


def audit_enabled_str(audit_enabled):
    if audit_enabled == 0:
        return "no auditing"
    elif audit_enabled == 1:
        return "auditing enabled"
    elif audit_enabled == 2:
        return "auditing enabled and configuration is locked/unchangeable."
    else:
        return ""


def audit_failure_str(audit_failure):
    if audit_failure == 0:
        return "AUDIT_FAIL_SILENT"
    elif audit_failure == 1:
        return "AUDIT_FAIL_PRINTK"
    elif audit_failure == 2:
        return "AUDIT_FAIL_PANIC"
    else:
        return ""


def get_audit_pid():
    audit_pid = -1
    try:
        audit_pid = readSymbol("audit_pid")
        return audit_pid
    except:
        pass

    try:
        ac = readSymbol("auditd_conn")
        pid = ac.pid
        audit_pid = pid.numbers[0].nr
        # To complicate to find 'current'.
        # So, no implementation for now for RHEL8
    except:
        pass

    return audit_pid


def get_task_from_pid(pid):
    try:
        task = readSU("struct task_struct", pid_to_task(pid))
    except:
        task = None

    return task


def show_audit_backlog(options):
    if not symbol_exists("audit_backlog_wait"):
        print("No audit_backlog_wait symbol exist")
        return

    audit_backlog_wait = readSymbol("audit_backlog_wait")
    print("audit_backlog_wait :", audit_backlog_wait)
    result = exec_crash_command("waitq 0x%x" % (audit_backlog_wait))
    print(result)


def get_hz():
    try:
        hz = sys_info.HZ
    except:
        hz = 0

    return hz if hz else 1000


def jiffies_to_str(jiffies_val):
    hz = get_hz()
    return "%s, HZ=%d" % (colored("%g sec" % (int(jiffies_val) / float(hz)),
                                  TIME_COLOR), hz)


def get_crash_wall_sec():
    """Wall clock seconds at crash time, or 0 if it can't be read"""
    try:
        timekeeper = readSymbol("tk_core").timekeeper
    except:
        try:
            timekeeper = readSymbol("timekeeper")
        except:
            timekeeper = None

    try:
        if timekeeper is not None:
            if member_offset("struct timekeeper", "xtime_sec") > -1:
                return int(timekeeper.xtime_sec)
            if member_offset("struct timekeeper", "xtime") > -1:
                return int(timekeeper.xtime.tv_sec)
        return int(readSymbol("xtime").tv_sec)
    except:
        return 0


def wall_sec_to_str(wall_sec):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(wall_sec))


# 'audit(<sec>.<msec>:<serial>)' at the start of every audit record
audit_stamp_re = re.compile(r"audit\((\d+)\.(\d+):\d+\)")


def get_record_time_str(record, crash_sec):
    if not isinstance(record, str):
        return ""
    match = audit_stamp_re.search(record)
    if match is None:
        return ""

    stamp = int(match.group(1)) + int(match.group(2)) / 1000.0
    result = "[%s" % (colored(wall_sec_to_str(int(stamp)), TIME_COLOR))
    if crash_sec:
        result = result + ", %s before crash" % \
            (colored("%.3f sec" % (crash_sec - stamp), AGE_COLOR))

    return result + "] "


def show_audit_status(options):
    audit_enabled = readSymbol("audit_enabled")
    audit_failure = readSymbol("audit_failure")
    audit_pid = get_audit_pid()
    audit_task = get_task_from_pid(audit_pid)
    rate_limit = readSymbol("audit_rate_limit")
    audit_backlog_limit = readSymbol("audit_backlog_limit")
    audit_lost = readSymbol("audit_lost").counter
    try:
        audit_queue = readSymbol("audit_skb_queue")
    except:
        audit_queue = readSymbol("audit_queue")

    audit_backlog_wait_time = readSymbol("audit_backlog_wait_time")

    print("%-17s %d (%s)" % ("enabled", audit_enabled,
                          audit_enabled_str(audit_enabled)))
    print("%-17s %d (%s)" % ("failure", audit_failure,
                          audit_failure_str(audit_failure)))
    try:
        print("%-17s %d (%s)" % ("pid", audit_pid, audit_task.comm))
    except:
        if symbol_exists("audit_sig_pid"):
            sig_pid = readSymbol("audit_sig_pid")
            if sig_pid != -1:
                print("%-17s %d" % ("auditd killed by", sig_pid))
        pass
    print("%-17s %d" % ("rate_limit", rate_limit))
    print("%-17s %d" % ("backlog_limit", audit_backlog_limit))
    print("%-17s %d" % ("lost", audit_lost))
    print("%-17s %d" % ("backlog", audit_queue.qlen))
    print("%-17s %d (%s)" % ("backlog_wait_time", audit_backlog_wait_time,
                             jiffies_to_str(audit_backlog_wait_time)))

    if (options.show_details):
        crash_sec = get_crash_wall_sec()
        print("----< details >----")
        print("struct sk_buff_head 0x%x" % (audit_queue))
        if crash_sec:
            print("crash time %s" % (colored(wall_sec_to_str(crash_sec), TIME_COLOR)))
        print("-" * 40)
        NLMSG_HDRLEN = struct_size("struct nlmsghdr")
        for sk_buff in readSUListFromHead(audit_queue,
                                          "next",
                                          "struct sk_buff",
                                          maxel=1000000):
            s = readmem(sk_buff.head + NLMSG_HDRLEN, sk_buff.tail - NLMSG_HDRLEN)
            if (s != None):
                try:
                    s = s.decode("UTF-8", "ignore")
                except:
                    pass
            print("%s%s" % (get_record_time_str(s, crash_sec), s))



def auditinfo():
    op = OptionParser()
    op.add_option("-b", "--backlog", dest="show_backlog", default=False,
                  action="store_true",
                  help="Show backlog process list")
    op.add_option("-d", "--details", dest="show_details", default=False,
                  action="store_true",
                  help="Show details if possible")
    op.add_option("-r", "--rules", dest="show_rules", default=False,
                  action="store_true",
                  help="Show audit rules")
    op.add_option("-s", "--status", dest="show_audit_status", default=False,
                  action="store_true",
                  help="Show audit status")

    (o, args) = op.parse_args()

    sys.setrecursionlimit(10**6)

    # Default action. Should be at the bottom
    if (o.show_rules):
        show_audit_rules(o)
        sys.exit(0)
    if (o.show_backlog):
        show_audit_backlog(o)
        sys.exit(0)

    show_audit_status(o)


if ( __name__ == '__main__'):
    auditinfo()
