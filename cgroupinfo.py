"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function

from pykdump.API import *

import sys
from optparse import OptionParser

import crashcolor

empty_count = 0
cgroup_count = 0


def cgroup_task_count(cgroup):
    count = 0
    for cg_cgroup_link in readSUListFromHead(cgroup.css_sets,
                                             'cgrp_link_list',
                                             'struct cg_cgroup_link'):
        count = count + cg_cgroup_link.cg.refcount.counter
    return count


def cgroup_task_list(cgroup, idx):
    for cg_cgroup_link in readSUListFromHead(cgroup.css_sets,
                                             'cgrp_link_list',
                                             'struct cg_cgroup_link'):
        for task in readSUListFromHead(cg_cgroup_link.cg.tasks,
                                       "cg_list",
                                       "struct task_struct"):
            for i in range(0, idx):
                print("\t", end="")
            print("\t0x%x %s(%d)" % (task, task.comm, task.pid))


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

def show_cgroup_tree(options):
    try:
        rootnode = readSymbol("rootnode")
        show_cgroup_tree_from_rootnode(rootnode, options)
        return
    except:
        pass

    try:
        cgroup_roots = readSymbol("cgroup_roots")
        show_cgroup_tree_from_cgroup_roots(cgroup_roots, options)
        return
    except:
        pass


def show_cgroup_tree_from_rootnode(rootnode, options):
    global empty_count
    global cgroup_count

    crashcolor.set_color(crashcolor.BLUE)
    print ("** cgroup subsystems **")
    crashcolor.set_color(crashcolor.RESET)
    for cgroup_subsys in readSUListFromHead(rootnode.subsys_list,
                                             'sibling',
                                             'struct cgroup_subsys'):
        print ("%s (0x%x)" % (cgroup_subsys.name, cgroup_subsys))
    print ("")
    crashcolor.set_color(crashcolor.BLUE)
    print ("** cgroup tree **")
    crashcolor.set_color(crashcolor.RESET)
    top_cgroup = rootnode.top_cgroup
    curlimit = sys.getrecursionlimit()
    sys.setrecursionlimit(1000)
    print_cgroup_entry(top_cgroup, top_cgroup, 0, options)
    sys.setrecursionlimit(curlimit)
    print ("-" * 70)
    crashcolor.set_color(crashcolor.BLUE)
    print ("Total number of cgroup(s) = %d, %d had 0 count" %
           (cgroup_count, empty_count))
    crashcolor.set_color(crashcolor.RESET)


def show_cgroup_tree_from_cgroup_roots(cgroup_roots, options):
    global empty_count
    global cgroup_count

    empty_count = 0
    cgroup_count = 0

    crashcolor.set_color(crashcolor.BLUE)
    print ("** cgroup tree **")
    crashcolor.set_color(crashcolor.RESET)
    for cgroup_root in readSUListFromHead(cgroup_roots,
                                          'root_list',
                                          'struct cgroup_root'):
        top_cgroup = cgroup_root.cgrp
        curlimit = sys.getrecursionlimit()
        sys.setrecursionlimit(1000)
        print_cgroup_entry(top_cgroup, top_cgroup, 0, options)
        sys.setrecursionlimit(curlimit)

    print ("-" * 70)
    crashcolor.set_color(crashcolor.BLUE)
    print ("Total number of cgroup(s) = %d, %d had 0 count" %
            (cgroup_count, empty_count))
    crashcolor.set_color(crashcolor.RESET)


def print_cgroup_entry(top_cgroup, cur_cgroup, idx, options):
    global empty_count
    global cgroup_count

    if (idx > 0 and top_cgroup == cur_cgroup):
        return
    if (cur_cgroup == 0):
        return

    e_count = 0
    for css_addr in cur_cgroup.subsys:
        if (css_addr == 0):
            continue
        subsys = readSU("struct cgroup_subsys_state", css_addr)
        if (subsys == 0):
            continue
        if (subsys.cgroup == 0):
            continue
        cgroup = subsys.cgroup
        cgroup_name = ""
        cgroup_counter = 0
        if member_offset("struct cgroup", "dentry") > -1:
            if (cgroup.dentry != 0):
                cgroup_name = dentry_to_filename(cgroup.dentry)
        elif member_offset("struct cgroup", "kn") > -1:
            cgroup_name = cgroup.kn.name

        cgroup_counter = cgroup_task_count(cgroup)
        if cgroup_name == "":
            cgroup_name = "<default>"

        if cgroup_counter == 0:
            crashcolor.set_color(crashcolor.RED)
            e_count = 1
        else:
            crashcolor.set_color(crashcolor.RESET)

        print ("%s%s%s at 0x%x (%d)" %
               ("  " * idx, "+--" if idx > 0 else "",
                cgroup_name, cgroup, cgroup_counter))
        if options.task_list:
            cgroup_task_list(cgroup, idx)
#        if (cgroup.parent == 0):
#            top_cgroup = cgroup

        head_of_list = None
        if member_offset("struct cgroup", "children") > -1:
            head_of_list = cgroup.children
            struct_name = "struct cgroup"
        elif member_offset("struct cgroup_subsys_state", "children") > -1:
            head_of_list = subsys.children
            struct_name = "struct cgroup_subsys_state"

        for childaddr in readSUListFromHead(head_of_list,
                                            'sibling', struct_name):
            if struct_name == "struct cgroup":
                cgroup = readSU(struct_name, childaddr)
            else:
                subsys_state = readSU(struct_name, childaddr)
                cgroup = subsys_state.cgroup

            print_cgroup_entry(top_cgroup, cgroup, idx + 1, options)

#        if (idx == 0):
#            print ("")
        if (cgroup == top_cgroup):
            continue


    cgroup_count = cgroup_count + 1
    empty_count = empty_count + e_count

    crashcolor.set_color(crashcolor.RESET)

    return


def show_task_group(options):
    global empty_count

    count = 0
    empty_count = 0
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
        cgroup_name = ""
        cgroup_counter = 0
        if member_offset("struct cgroup", "dentry") > -1:
            if (cgroup.dentry != 0):
                cgroup_name = dentry_to_filename(cgroup.dentry)
        elif member_offset("struct cgroup", "kn") > -1:
            cgroup_name = cgroup.kn.name

        cgroup_counter = cgroup_task_count(cgroup)
        if cgroup_name == "":
            cgroup_name = "<default>"

        if cgroup_counter == 0:
            crashcolor.set_color(crashcolor.RED)
            empty_count = empty_count + 1
        else:
            crashcolor.set_color(crashcolor.RESET)

        print ("task_group = 0x%x, cgroup = 0x%x, counter=%d\n\t(%s)" %
                (task_group, cgroup, cgroup_counter, cgroup_name))
        if options.task_list:
            cgroup_task_list(cgroup, 0)

        crashcolor.set_color(crashcolor.RESET)

    print ("-" * 70)
    crashcolor.set_color(crashcolor.BLUE)
    print ("Total number of task_group(s) = %d, %d had 0 count" %
           (count, empty_count))
    crashcolor.set_color(crashcolor.RESET)



def cgroupinfo():
    global empty_count
    global cgroup_count

    op = OptionParser()
    op.add_option("-g", "--tglist", dest="taskgroup_list", default=0,
                  action="store_true",
                  help="task_group list")

    op.add_option("-t", "--tree", dest="cgroup_tree", default=0,
                  action="store_true",
                  help="hierarchial display of cgroups")

    op.add_option("-l", "--tasklist", dest="task_list", default=0,
                  action="store_true",
                  help="Shows task list in cgroup")

    (o, args) = op.parse_args()

    cgroup_count = 0
    empty_count = 0

    if (o.taskgroup_list):
        show_task_group(o)
#        sys.exit(0)

    if (o.cgroup_tree):
        show_cgroup_tree(o)
#        sys.exit(0)

    # show_task_group()


if ( __name__ == '__main__'):
    cgroupinfo()
