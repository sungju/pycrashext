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

def show_cgroup_tree():
    rootnode = readSymbol("rootnode")
    if (rootnode == 0):
        return
    print ("** cgroup subsystems **")
    for cgroup_subsys in readSUListFromHead(rootnode.subsys_list,
                                             'sibling',
                                             'struct cgroup_subsys'):
        print ("%s (0x%x)" % (cgroup_subsys.name, cgroup_subsys))

    print ("")
    print ("** cgroup tree **")
    top_cgroup = rootnode.top_cgroup
    curlimit = sys.getrecursionlimit()
    sys.setrecursionlimit(100)
    print_cgroup_entry(top_cgroup, top_cgroup, 0)
    sys.setrecursionlimit(curlimit)

def print_cgroup_entry(top_cgroup, cur_cgroup, idx):
    if (idx > 0 and top_cgroup == cur_cgroup):
        return
    if (cur_cgroup == 0):
        return
    for css_addr in cur_cgroup.subsys:
        if (css_addr == 0):
            continue
        subsys = readSU("struct cgroup_subsys_state", css_addr)
        if (subsys == 0):
            continue
        if (subsys.cgroup == 0):
            continue
        cgroup = subsys.cgroup
        cgroup_name = "<default>"
        if (cgroup.dentry != 0):
            cgroup_name = dentry_to_filename(cgroup.dentry)
        print ("%s%s%s at 0x%x" %
               ("  " * idx, "+--" if idx > 0 else "", cgroup_name, cgroup))
        if (cgroup.parent == 0):
            top_cgroup = cgroup


        for childaddr in readSUListFromHead(cgroup.children,
                                            'sibling', 'struct cgroup'):
            cgroup = readSU('struct cgroup', childaddr)
            print_cgroup_entry(top_cgroup, cgroup, idx + 1)

#        if (idx == 0):
#            print ("")
        if (cgroup == top_cgroup):
            continue

    return


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
        if (cgroup == 0):
            continue
        count = count + 1
        cgroup_name = "<default>"
        if (cgroup.dentry != 0):
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

    op.add_option("--tree", dest="cgroup_tree", default=0,
                  action="store_true",
                  help="hierarchial display of cgroups")

    (o, args) = op.parse_args()

    if (o.taskgroup_list):
        show_task_group()
        sys.exit(0)

    if (o.cgroup_tree):
        show_cgroup_tree()
        sys.exit(0)

    show_task_group()


if ( __name__ == '__main__'):
    cgroupinfo()
