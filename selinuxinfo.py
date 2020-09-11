"""
 Written by Amit Kumar Das
 Date Sep 2020
 Python3
 py tool to verify selinux status in crash utility
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
def show_status():
    se_enb = readSymbol("selinux_enabled")
    se_dis = readSymbol("selinux_disabled")
    se_enf = readSymbol("selinux_enforcing")
   
    if ((se_enb == 1) and (se_enf == 1)):
        print ("SELinux status: %s \nSELinux mode: %s" % (enb, enf))
    elif ((se_enb == 1) and (se_enf == 0)):
        print ("SELinux status: %s \nSELinux mode: %s" % (enb, perm))
    elif (se_dis == 1):
        print ("SELinux status: %s" % dis)
    else:
        pass
    '''all kernel_symbol return 0 when selinux=0 is
    added explicity as kernel boot parameter.
    elif ((se_enb == 0) and (se_dis == 0)):
        print("Disabled, selinux=0 used in boot")''' 
    
    print ("\nkernel_symbol %6s value" %'')
    print ("selinux_enabled %6d" % se_enb)
    print ("selinux_disable %6d" % se_dis)
    print ("selinux_enforcing %4d" % se_enf)


# Show basic selinux details
def show_info():
    print(info)


# defining options
def selinuxinfo():
    op = OptionParser()
    
    op.add_option("-s", "--status", dest="status", 
            default=0, action="store_true",
            help="show selinux status")
    op.add_option("-i", "--info", dest="info",
            default=0, action="store_true",
            help="show selinux policy information")

    (opt, args) = op.parse_args()

    if (opt.status):
        show_status()
        sys.exit(0)
    if (opt.info):
        show_info()
        sys.exit(0)


if (__name__ == '__main__'):
    selinuxinfo()

#EOF
