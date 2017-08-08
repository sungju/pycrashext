from __future__ import print_function

from pykdump.API import *

import sys
from optparse import OptionParser

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

def show_task_group():
    count = 0
    for task_group in readSUListFromHead(sym2addr('task_groups'),
                                         'list', 'struct task_group'):
        css = readSU('struct cgroup_subsys_state', task_group.css)
        if (css == 0):
            continue
        if (css.cgroup == 0):
            continue
        cgroup = readSU('struct cgroup', css.cgroup)
        count = count + 1
        cgroup_name = dentry_to_filename(cgroup.dentry)
        print ("task_group = 0x%16x, cgroup = 0x%16x\n\t(%s)" %
                (task_group, cgroup, cgroup_name))

    print ("-" * 70)
    print ("Total number of task_group(s) = %d" % (count))



def cgroupinfo():
    op = OptionParser()
    op.add_option("--tglist", dest="taskgroup_list", default=0,
                  action="store_true",
                  help="task_group list")

    (o, args) = op.parse_args()

    if (o.taskgroup_list):
        show_task_group()
        sys.exit(0)


    show_task_group()


if ( __name__ == '__main__'):
    cgroupinfo()
