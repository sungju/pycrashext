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

cgroup_subsys_func_list = {}


def cpu_cgroup_subsys_detail(task_group, cgroup, subsys, idx):
    cfs_period_us = task_group.cfs_bandwidth.period.tv64 / 1000
    cfs_quota_us = task_group.cfs_bandwidth.quota / 1000
    throttled_cfs_rq = task_group.cfs_bandwidth.throttled_cfs_rq
    throttled_time = task_group.cfs_bandwidth.throttled_time
    if throttled_time > 0:
        throttled_time = throttled_time / 1000000000
    pre_str = "\t"
    for i in range(0, idx):
        pre_str = pre_str + "\t"
    print("%scpu.cfs_period_us = %d, cpu.cfs_quota_us = %d, throttled_time = %d secs" %
          (pre_str, cfs_period_us, cfs_quota_us, throttled_time))
    for cfs_rq in readSUListFromHead(throttled_cfs_rq,
                                     "throttled_list",
                                     "struct cfs_rq",
                                     maxel=1000000):
        print("%scfs_rq 0x%x, nr_running = %d, throttled = %d" %
              (pre_str, cfs_rq, cfs_rq.nr_running, cfs_rq.throttled))
        for se in readSUListFromHead(cfs_rq.tasks,
                                     "group_node",
                                     "struct sched_entity",
                                     maxel=1000000):
            offset = member_offset("struct task_struct", "se")
            task = readSU("struct task_struct", Addr(se) - offset)
            print("%s\ttask_struct 0x%x, %s(%d)" % (pre_str, task, task.comm, task.pid))


def get_subsys_func_addr(subsys_id):
    if subsys_id == "cpuset_subsys_id":
        return  None
    elif subsys_id == "ns_subsys_id":
        return  None
    elif subsys_id == "cpu_cgroup_subsys_id":
        return  cpu_cgroup_subsys_detail
    elif subsys_id == "cpuacct_subsys_id":
        return  None
    elif subsys_id == "mem_cgroup_subsys_id":
        return  None
    elif subsys_id == "devices_subsys_id":
        return  None
    elif subsys_id == "freezer_subsys_id":
        return  None
    elif subsys_id == "net_cls_subsys_id":
        return  None
    elif subsys_id == "blkio_subsys_id":
        return  None
    elif subsys_id == "perf_subsys_id":
        return  None
    elif subsys_id == "net_prio_subsys_id":
        return  None
    else:
        return None


def cgroup_subsys_id_init():
    global cgroup_subsys_func_list

    cgroup_subsys_func_list = {}
    cgroup_subsys_id = EnumInfo("enum cgroup_subsys_id")
    for enum_name in cgroup_subsys_id:
        id = cgroup_subsys_id[enum_name]
        cgroup_subsys_func_list[id] = get_subsys_func_addr(enum_name)


def cgroup_details(task_group, cgroup, idx):
    subsys_idx = -1
    for subsys in cgroup.subsys:
        subsys_idx = subsys_idx + 1
        if subsys is None or subsys == 0:
            continue
        subsys_func = cgroup_subsys_func_list[subsys_idx]
        if subsys_func == None:
            continue
        subsys_func(task_group, cgroup, subsys, idx)


def cgroup_task_count(cgroup):
    count = 0
    for cg_cgroup_link in readSUListFromHead(cgroup.css_sets,
                                             'cgrp_link_list',
                                             'struct cg_cgroup_link',
                                             maxel=1000000):
        count = count + cg_cgroup_link.cg.refcount.counter
    return count


def cgroup_task_list(cgroup, idx):
    for cg_cgroup_link in readSUListFromHead(cgroup.css_sets,
                                             'cgrp_link_list',
                                             'struct cg_cgroup_link',
                                             maxel=1000000):
        for task in readSUListFromHead(cg_cgroup_link.cg.tasks,
                                       "cg_list",
                                       "struct task_struct",
                                       maxel=1000000):
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
                                             'struct cgroup_subsys',
                                            maxel=1000000):
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
                                          'struct cgroup_root',
                                          maxel=1000000):
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
                                            'sibling', struct_name,
                                            maxel=1000000):
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
                                         'list', 'struct task_group',
                                         maxel=1000000):
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
        if options.show_detail:
            cgroup_details(task_group, cgroup, 0)

        if options.task_list:
            cgroup_task_list(cgroup, 0)

        crashcolor.set_color(crashcolor.RESET)

    print ("-" * 70)
    crashcolor.set_color(crashcolor.BLUE)
    print ("Total number of task_group(s) = %d, %d had 0 count" %
           (count, empty_count))
    crashcolor.set_color(crashcolor.RESET)


total_count = 0

def show_mem_cgroup(mem_cgroup_addr, depth, idx):
    space_str = "\t" * depth
    if mem_cgroup_addr == 0:
        crashcolor.set_color(crashcolor.BLUE)
        print("%s%d: mem_cgroup 0x0" % (space_str, idx))
        crashcolor.set_color(crashcolor.RESET)
        return
    try:
        mem_cgroup = readSU("struct mem_cgroup", mem_cgroup_addr)
    except:
        return

    print("%s%d: mem_cgroup 0x%x : id = %d, refcnt = %d, dead_count = %d" %
          (space_str, idx, mem_cgroup, mem_cgroup.id,
           mem_cgroup.refcnt.counter, mem_cgroup.dead_count.counter))


def show_idr_layer(idr_layer, max_layer, depth = 0, index=-1,
                   show_all=False, show_details=False):
    global total_count

    space_str = "\t" * depth
    idx_str = ""
    if index >= 0:
        idx_str = "ary[%d] : " % index

    print("%s%sidr_layer 0x%x" % (space_str, idx_str, idr_layer))
    print("%s  count = %d" % (space_str, idr_layer.count))
    print("%s  layer = %d" % (space_str, idr_layer.layer))
    int_size = getSizeOf("int")
    long_size = getSizeOf("long")
    IDR_BITS=8
    IDR_SIZE=(1 << IDR_BITS)

    if idr_layer.layer == 0:
        total_count = total_count + idr_layer.count

    idx = 0
    for bitmap in idr_layer.bitmap:
        if idr_layer.layer > 0:
            print("%s  bitmap[%d] = 0x%x" % (space_str, idx / (long_size * long_size), bitmap))
        mask = 1
        while mask <= 0xffffffffffffffff:
            if bitmap & mask == mask:
                if idr_layer.layer > 0:
                    show_idr_layer(idr_layer.ary[idx], max_layer, depth + 1,
                                   idx, show_all, show_details)
                elif show_details:
                    show_mem_cgroup(idr_layer.ary[idx], depth + 1, idx)


            elif show_all:
                if idr_layer.layer > 0:
                    crashcolor.set_color(crashcolor.RED)
                    show_idr_layer(idr_layer.ary[idx], max_layer, depth + 1,
                                   idx, show_all, show_details)
                    crashcolor.set_color(crashcolor.RESET)
                elif show_details:
                    show_mem_cgroup(idr_layer.ary[idx], depth + 1, idx)

            bitmap = bitmap & ~mask
            idx = idx + 1
            mask = mask << 1
        if idr_layer.layer > 0:
            print("")


def show_mem_cgroup_idr(options):
    global total_count

    mem_cgroup_idr = readSymbol("mem_cgroup_idr")
    print(mem_cgroup_idr)
    print("hint = 0x%x" % (mem_cgroup_idr.hint))
    print("top = 0x%x" % (mem_cgroup_idr.top))
    print("layers = %d" % (mem_cgroup_idr.layers))
    print("id_free_cnt = %d" % (mem_cgroup_idr.id_free_cnt))
    print("cur = %d" % (mem_cgroup_idr.cur))

    print("")
    show_idr_layer(mem_cgroup_idr.top, mem_cgroup_idr.layers, 0, -1,
                  options.mem_cgroup_idr_all, options.show_detail)


    print("\nTotal allocated count = %d" % (total_count))


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

    op.add_option("-d", "--detail", dest="show_detail", default=0,
                  action="store_true",
                  help="Shows cgroup details")

    op.add_option("-i", "--idr", dest="mem_cgroup_idr", default=0,
                  action="store_true",
                  help="mem_cgroup_idr detail")

    op.add_option("-I", "--IDR", dest="mem_cgroup_idr_all", default=0,
                  action="store_true",
                  help="mem_cgroup_idr detail include free entries")

    (o, args) = op.parse_args()

    cgroup_count = 0
    empty_count = 0
    cgroup_subsys_id_init()

    if (o.mem_cgroup_idr or o.mem_cgroup_idr_all):
        show_mem_cgroup_idr(o)
        sys.exit(0)

    if (o.taskgroup_list):
        show_task_group(o)
#        sys.exit(0)

    if (o.cgroup_tree):
        show_cgroup_tree(o)
#        sys.exit(0)

    # show_task_group()


if ( __name__ == '__main__'):
    cgroupinfo()
