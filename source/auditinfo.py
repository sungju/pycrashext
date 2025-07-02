"""
auditinfo
=========

Show 'audit' related information.

 Written by Daniel Sungju Kwon
"""
from pykdump.API import *

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
    Audit_equal : "equal",
    Audit_not_equal : "not_equal",
    Audit_bitmask : "bitmask",
    Audit_bittest : "bittest",
    Audit_lt : "<",
    Audit_gt : ">",
    Audit_le : "<=",
    Audit_ge : ">=",
    Audit_bad : "bad",
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


# Rule flags
AUDIT_FILTER_PREPEND = 0x10
AUDIT_FILTER_USER   = 0x00    # Apply rule to user-generated messages
AUDIT_FILTER_TASK   = 0x01    # Apply rule at task creation (not syscall)
AUDIT_FILTER_ENTRY  = 0x02    # Apply rule at syscall entry
AUDIT_FILTER_WATCH  = 0x03    # Apply rule to file system watches
AUDIT_FILTER_EXIT   = 0x04    # Apply rule at syscall exit
AUDIT_FILTER_TYPE   = 0x05    # Apply rule at audit_log_start


audit_flag_dict =  {
    AUDIT_FILTER_USER : "user",
    AUDIT_FILTER_TASK : "task",
    AUDIT_FILTER_ENTRY : "syscall",
    AUDIT_FILTER_WATCH : "watch",
    AUDIT_FILTER_EXIT :  "exit",
    AUDIT_FILTER_TYPE : "start",
}


def get_audit_flag_str(flags):
    result = ""
    for key in audit_flag_dict:
        if (key & flags) == key:
            if result != "":
                result = result + ","
            result = result + audit_flag_dict[key]

    if result ==  "":
        result = "%d" % flags

    return  result


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

audit_perm_dict = {
    AUDIT_PERM_EXEC  : "e",
    AUDIT_PERM_WRITE : "w",
    AUDIT_PERM_READ  : "r",
    AUDIT_PERM_ATTR  : "a",
}


def get_audit_perm_str(val):
    result = ""
    for key in audit_perm_dict:
        if (key & val) == key:
            result = result + audit_perm_dict[key]

    if result ==  "":
        result = "%s" % val

    return result


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


def get_audit_dir_str(audit_rule):
    pathname = read_string(audit_rule.tree.pathname)

    return pathname


def get_audit_val_str(ftype, fval, audit_entry):
    val_str = ""
    if ftype == AUDIT_ARCH:
        val_str = "-F %s" % (get_audit_arch_str(fval))
    elif ftype == AUDIT_PERM:
        val_str = "-p %s" % (get_audit_perm_str(fval))
    elif ftype == AUDIT_DIR:
        val_str = "-w %s " % (get_audit_dir_str(audit_entry.rule))
    else:
        pass
        #val_str = "%d" % (fval if int(fval) < 4294967283 else -1)

    return val_str


def get_audit_fields_details(audit_entry):
    rule = audit_entry.rule
    result_str = ""

    for i in range(0, rule.field_count):
        field = rule.fields[i]
        result_str = result_str + get_audit_val_str(field.type, field.val, \
                                                    audit_entry)

    return result_str


def get_mask_str(masks):
    result_str = ""
    idx = 0
    enabled_syscalls = []
    for index, value in enumerate(masks):
        for bit in range(32):
            if value & (1 << bit):
                syscall_number = index * 32 + bit
                enabled_syscalls.append(syscall_number)

    if len(enabled_syscalls) > 0:
        result_str = ",".join(str(x) for x in enabled_syscalls)

    result_str = ''

    return result_str


def show_audit_rules(options):
    audit_rules_list = readSymbol("audit_rules_list")
    offset = member_offset("struct audit_entry", "rule")
    offset = offset + member_offset("struct audit_krule", "list")

    for audit_rules in audit_rules_list:
        next_addr = audit_rules.next
        while next_addr != audit_rules:
            audit_entry = readSU("struct audit_entry", next_addr - offset)
            result_str = ""
            if audit_entry.rule.watch:
                result_str = "-w %s" % audit_entry.rule.watch.path
            flag_str = get_audit_flag_str(audit_entry.rule.flags & ~AUDIT_FILTER_PREPEND)
            action_str = get_audit_action_str(audit_entry.rule.action)
            listnr_str = get_audit_flag_str(audit_entry.rule.listnr)
            if action_str != "":
                if listnr_str != "":
                    listnr_str = "," + listnr_str + get_mask_str(audit_entry.rule.mask)
                result_str = result_str + (" -a %s" % (action_str + listnr_str))

            if audit_entry.rule.field_count > 0:
                result_str = result_str + (" %s" % get_audit_fields_details(audit_entry))
            filter_key = audit_entry.rule.filterkey
            if filter_key != "":
                result_str = result_str + (" -k %s" % filter_key)


            print("struct audit_entry 0x%x\n\t%s" % (audit_entry, result_str))
            next_addr = audit_entry.rule.list.next


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
    print("%-17s %d" % ("backlog_wait_time", audit_backlog_wait_time))

    if (options.show_details):
        print("----< details >----")
        print("struct sk_buff_head 0x%x" % (audit_queue))
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
            print("%s" % (s))



def auditinfo():
    op = OptionParser()
    op.add_option("-r", "--rules", dest="show_rules", default=False,
                  action="store_true",
                  help="Show audit rules")
    op.add_option("-s", "--status", dest="show_audit_status", default=False,
                  action="store_true",
                  help="Show audit status")
    op.add_option("-d", "--details", dest="show_details", default=False,
                  action="store_true",
                  help="Show details if possible")

    (o, args) = op.parse_args()

    sys.setrecursionlimit(10**6)

    # Default action. Should be at the bottom
    if (o.show_rules):
        show_audit_rules(o)
        sys.exit(0)

    show_audit_status(o)


if ( __name__ == '__main__'):
    auditinfo()
