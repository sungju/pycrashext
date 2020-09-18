"""
 Written by Amit Kumar Das
 Date Sep 2020
 py3 tool to verify selinux status in crash utility
"""

from pykdump.API import *
from optparse import OptionParser

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

# Verifying SELinux kernel symbol
se_enb = readSymbol("selinux_enabled")
se_enf = readSymbol("selinux_enforcing")
se_dis = readSymbol("selinux_disabled")

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
    if ((se_enb == 1) and (se_enf == 1) and (se_dis == 0)):
        print ("\nSELinux status: %s \nSELinux mode: %s" % (enb, enf))
    elif ((se_enb == 1) and (se_enf == 0) and  (se_dis == 0)):
        print ("\nSELinux status: %s \nSELinux mode: %s" % (enb, perm))
    elif ((se_enb == 0) and (se_enf ==0) and (se_dis == 1)):
        print ("\nSELinux status: %s" % dis)
    elif ((se_enb == 0) and (se_enf == 0) and (se_dis == 0)):
        print ("\nSELinux status: %s" % dis)
    else:
        pass

    se_retrun = show_seboot()


# prining all selinux kernel symbol
def show_ksymbol():
    print ("\nkernel_symbol %6s value" %'')
    print ("selinux_enabled %6d" % se_enb)
    print ("selinux_enforcing %4d" % se_enf)
    print ("selinux_disable %6d" % se_dis)

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


# Show mountfs information
def show_fsmount():
    pass #RFE

# defining options
def selinuxinfo():
    op = OptionParser()
    
    op.add_option("-s", "--status", dest="status", 
            default=0, action="store_true",
            help="show selinux status")
    op.add_option("-i", "--info", dest="info",
            default=0, action="store_true",
            help="show selinux policy information")
    op.add_option("-f", "--fsmount", dest="fsmount",
            default=0, action="store_true",
            help="show selinux fs mount informationn")

    (opt, args) = op.parse_args()

    if (opt.status):
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
