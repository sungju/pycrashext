"""
'selinuxinfo' command: SELinux status and policy information.

Written by Amit Kumar Das
"""

from pykdump.API import *
from optparse import OptionParser

import re
import sys
import crashcolor

info="""
enforcing   SELinux policy is enforced.
permissive  SELinux prints warnings instead of enforcing.
disabled    No SELinux policy loaded.
"""

# define
enf="enforcing"
perm="permissive"
dis="disabled"
enb="enabled"


def read_int(names):
    """(value, symbol) of the first of names in this kernel, or (None, None)"""
    for name in names:
        if symbol_exists(name):
            try:
                return int(readSymbol(name)), name
            except Exception:
                pass
    return None, None


def read_selinux_state():
    """
    [(name, value, source symbol)] for enabled, enforcing and disabled.
    Older kernels keep them in the selinux_enabled, selinux_enforcing and
    selinux_disabled ints. Newer ones (RHEL8.10, RHEL9, RHEL10) keep
    enforcing and disabled in struct selinux_state, which lost 'disabled' in
    6.4 (RHEL10) along with runtime disabling. Their selinux_enabled_boot is
    __initdata, freed after boot, so 'enabled' comes from
    selinux_state.initialized instead: a policy was loaded. A value the
    kernel does not have is None.
    """
    state = None
    if symbol_exists("selinux_state"):
        try:
            state = readSymbol("selinux_state")
        except Exception:
            state = None

    def from_state(field):
        if state is None or \
                member_offset("struct selinux_state", field) < 0:
            return None, None
        return int(getattr(state, field)), "selinux_state." + field

    result = []
    for name, symbol, field in (("enabled", "selinux_enabled", "initialized"),
                                ("enforcing", "selinux_enforcing", "enforcing"),
                                ("disabled", "selinux_disabled", "disabled")):
        value, source = read_int((symbol,))
        if value is None:
            value, source = from_state(field)
        result.append((name, value, source))
    return result


se_state = read_selinux_state()
se_enb, se_enf, se_dis = [v if v is not None else 0 for n, v, s in se_state]
se_present = any(src is not None for n, v, src in se_state)

'''
 listing all possible values
 se_enb se_enf  se_dis 
     0       0       0  #selinux=0
     0       0       1  #disabled
     0       1       0
     0       1       1
     1       0       0  #enabled, permisive, enforcing=0
     1       0       1
     1       1       0  #enabled, enforcing, selinux=1, enforcing=1
     1       1       1
'''

# Stauts code verification
def show_status():
    if not se_present:
        print("\nSELinux is not in this kernel")
        return
    if ((se_enb == 1) and (se_enf == 1) and (se_dis == 0)):
        print ("\nSELinux status: %s \nSELinux mode: %s" % (enb, enf))
    elif ((se_enb == 1) and (se_enf == 0) and  (se_dis == 0)):
        print ("\nSELinux status: %s \nSELinux mode: %s" % (enb, perm))
    elif ((se_enb == 0) and (se_enf ==0) and (se_dis == 1)):
        print ("\nSELinux status: %s" % dis)
    elif ((se_enb == 0) and (se_enf == 0) and (se_dis == 0)):
        print ("\nSELinux status: %s" % dis)
    else:
        print ("\nSELinux status: unexpected combination: enabled=%d "
               "enforcing=%d disabled=%d (see -d)" % (se_enb, se_enf, se_dis))

    se_retrun = show_seboot()


# prining all selinux kernel symbol
def show_ksymbol():
    print ("\n%-26s value" % "kernel_symbol")
    for name, value, source in se_state:
        if source is None:
            print ("%-26s %5s   (%s: not in this kernel)" % ("-", "-", name))
        else:
            print ("%-26s %5d" % (source, value))

# Show basic selinux details
def show_info():
    print(info)

'''
 verifying selinux and enforcing added
 explicity as kernel boot parameter.
'''
def show_seboot():
    se_boot = readSymbol("saved_command_line")
    if ("selinux" in se_boot):
        print ("\n'selinux' used in kernel boot parameter: \n%s" % se_boot)
    elif ("enforcing" in se_boot):
        print ("\n'enforcing' used in kernel boot parameter: \n%s" % se_boot)
    else:
        pass

    return se_boot


# searching super_block value in mount list
def show_selinuxfs(sb):
    mnt_list = exec_crash_command("mount")
    mnt_list = mnt_list.splitlines()
    print ('\n', mnt_list[0])

    retval = 0
    for mline in mnt_list:
        word = mline.split()
        if len(word) > 2 and (word[1] == sb or
                              (sb is None and word[2] == "selinuxfs")):
            print (mline)
            retval = 1

    if retval == 0:
        print (" selinuxfs is not mounted in this mount namespace")

    return retval


# Show mountfs information
def show_fsmount():
    """
    selinuxfs is kern_mount()ed into selinuxfs_mount before 5.x and into
    selinux_null.mnt from RHEL9; the mounts of that superblock (normally
    /sys/fs/selinux) are what 'mount' shows.
    """
    if (se_enb != 1):
        print ("\nSELinux is not enabled, so selinuxfs is not set up")
        return

    se_mnt = None
    try:
        if symbol_exists('selinuxfs_mount'):
            se_mnt = readSymbol('selinuxfs_mount')
        elif symbol_exists('selinux_null'):
            se_mnt = readSymbol('selinux_null').mnt
    except Exception:
        se_mnt = None

    if se_mnt:
        print ('\n', se_mnt, '\n', se_mnt.mnt_sb)
        # 'mount' prints the super_block address without 0x
        show_selinuxfs("%x" % int(se_mnt.mnt_sb))
    else:
        show_selinuxfs(None)

# defining options
def selinuxinfo():
    op = OptionParser()
    
    op.add_option("-d", "--detail", dest="detail", 
            default=0, action="store_true",
            help="show selinux status")
    op.add_option("-i", "--info", dest="info",
            default=0, action="store_true",
            help="show selinux basic policy")
    op.add_option("-f", "--fsmount", dest="fsmount",
            default=0, action="store_true",
            help="show selinux fs mount informationn")

    (opt, args) = op.parse_args()

    if not (opt.detail or opt.info or opt.fsmount):
        show_status()
        sys.exit(0)
    if (opt.detail):
        show_status()
        show_ksymbol()
        sys.exit(0)
    if (opt.info):
        show_info()
        sys.exit(0)
    if (opt.fsmount):
        show_fsmount()
        sys.exit(0)

if (__name__ == '__main__'):
    selinuxinfo()

#EOF
