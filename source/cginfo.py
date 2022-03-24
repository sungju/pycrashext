"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function

from pykdump.API import *
from LinuxDump.trees import *

import sys
import operator
from optparse import OptionParser

import crashcolor

PAGE_SIZE = 4096

empty_count = 0
cgroup_count = 0

cgroup_subsys_func_list = {}

first_ksymbol = 0

def check_global_symbols():
    global first_ksymbol

    try:
        help_s_out = exec_crash_command("help -s")
        lines = help_s_out.splitlines()
        for line in lines:
            words = line.split(":")
            if words[0].strip() == "first_ksymbol":
                first_ksymbol = int(words[1].split()[0], 16)
                return
    except Exception as e:
        pass

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


cgroup_subsys_id_list = {}

def cgroup_subsys_id_init():
    global cgroup_subsys_func_list
    global cgroup_subsys_id_list

    cgroup_subsys_func_list = {}
    cgroup_subsys_id_list = {}
    cgroup_subsys_id = EnumInfo("enum cgroup_subsys_id")
    for enum_name in cgroup_subsys_id:
        id = cgroup_subsys_id[enum_name]
        cgroup_subsys_func_list[id] = get_subsys_func_addr(enum_name)
        cgroup_subsys_id_list[id] = enum_name


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
    if member_offset("struct cgroup", "css_sets") >= 0:
        list_start = cgroup.css_sets
        entry_name = "cgrp_link_list"
        struct_name = "struct cg_cgroup_link"
    elif member_offset("struct cgroup", "cset_links") >= 0:
        list_start = cgroup.cset_links
        entry_name = "cset_link"
        struct_name = "struct cgrp_cset_link"
    else:
        return 0

    for cg_cgroup_link in readSUListFromHead(list_start,
                                             entry_name,
                                             struct_name,
                                             maxel=1000000):
        if struct_name == "struct cg_cgroup_link":
            count = count + cg_cgroup_link.cg.refcount.counter
        elif struct_name == "struct cgrp_cset_link":
            count = count + cg_cgroup_link.cset.nr_tasks
        else:
            break

    return count


def cgroup_task_list(cgroup, idx):
    if member_offset("struct cgroup", "css_sets") >= 0:
        list_start = cgroup.css_sets
        entry_name = "cgrp_link_list"
        struct_name = "struct cg_cgroup_link"
    elif member_offset("struct cgroup", "cset_links") >= 0:
        list_start = cgroup.cset_links
        entry_name = "cset_link"
        struct_name = "struct cgrp_cset_link"
    else:
        return 0

    for cg_cgroup_link in readSUListFromHead(list_start,
                                             entry_name,
                                             struct_name,
                                             maxel=1000000):
        if struct_name == "struct cg_cgroup_link":
            task_list = cg_cgroup_link.cg.tasks
        elif struct_name == "struct cgrp_cset_link":
            task_list = cg_cgroup_link.cgrp.tasks
        else:
            break

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


def show_cgroup2_file_detail(options, kernfs_node, idx):
    global first_ksymbol

    cgroup = readSU("struct cgroup", kernfs_node.parent.priv)
    cftype = readSU("struct cftype", kernfs_node.priv)
    ss = cftype.ss
#    print(cgroup) # DEBUG
#    print(cftype) # DEBUG
    if ss != None and ss != 0 and int(ss) >= first_ksymbol:
        ss_id = ss.id
        ss_name = ss.name
        css = cgroup.subsys[ss_id]
    else:
        css = cgroup.self
        ss = css.ss
        if ss != None and ss != 0:
            ss_name = ss.name
        elif cftype.name.startswith("cgroup."):
            ss_name = cftype.name
        else:
            print("")
            return

    idx_str = "  " * idx + "      `"
    if ss_name == "memory":
        show_memory_value(kernfs_node, cgroup, cftype, ss, css)
    elif ss_name == "cpu":
        show_cpu_value(kernfs_node, cgroup, cftype, ss, css)
    elif ss_name.startswith("cgroup."):
        show_cgroup_value(kernfs_node, cgroup, cftype, ss, css)
    else:
        print("")
        print("%s%s (0x%x)" % (idx_str, ss_name, css))

    #print(cftype)


def show_cpu_value_max(tg):
    cfs_period = tg.cfs_bandwidth.period / 1000
    cfs_quota = tg.cfs_bandwidth.quota
    if cfs_quota == 18446744073709551615: # RUNTIME_INF     ((u64)~0ULL)
        cfs_quota = -1
    else:
        cfs_quota = cfs_quota / 1000

    quota_str = "max" if cfs_quota < 0 else ("%d" % cfs_quota)
    print(" = %s %d" % (quota_str, cfs_period))


def show_cpu_value_weight(tg):
    CGROUP_WEIGHT_DFL=100
    weight = tg.shares * CGROUP_WEIGHT_DFL
    weight = weight / (1024/2)
    print(" = %d" % (weight))


MAX_NICE = 19
MIN_NICE = -20
NICE_WIDTH = (MAX_NICE - MIN_NICE + 1)
MAX_RT_PRIO = 100
DEFAULT_PRIO = (MAX_RT_PRIO + NICE_WIDTH / 2)

def show_cpu_value_weight_nice(tg):
    weight = tg.shares
    last_delta = sys.maxsize
    sched_prio_to_weight = readSymbol("sched_prio_to_weight")
    prio = 0

    for i in range(0, len(sched_prio_to_weight)):
        delta = abs(sched_prio_to_weight[i] - weight)
        prio = i
        if delta >= last_delta:
            break
        last_delta = delta

    weight = (prio - 1 + MAX_RT_PRIO) - DEFAULT_PRIO
    print(" = %d" % (weight))


def show_cpu_value_burst(tg):
    burst = tg.cfs_bandwidth.burst / 1000
    print(" = %d" % (burst))


def show_cpu_value_idle(tg):
    print(" = %d" % (tg.idle))


def show_cpu_value(kn, cgroup, cftype, ss, css):
    css_offset = member_offset("struct task_group", "css")
    tg = readSU("struct task_group", css - css_offset)
    crashcolor.set_color(crashcolor.BLUE)
    if kn.name.endswith(".max"):
        show_cpu_value_max(tg)
    elif kn.name.endswith(".weight"):
        show_cpu_value_weight(tg)
    elif kn.name.endswith(".weight.nice"):
        show_cpu_value_weight_nice(tg)
    elif kn.name.endswith(".burst"):
        show_cpu_value_burst(tg)
    elif kn.name.endswith(".idle"):
        show_cpu_value_idle(tg)
    else:
        print("")
    crashcolor.set_color(crashcolor.RESET)
        


def show_memory_value(kn, cgroup, cftype, ss, css):
    css_offset = member_offset("struct mem_cgroup", "css")
    mem_cgroup = readSU("struct mem_cgroup", css - css_offset)
    crashcolor.set_color(crashcolor.BLUE)
    if kn.name.endswith(".max"):
        print(" = %d" % (mem_cgroup.memory.max))
    elif kn.name.endswith(".high"):
        print(" = %d" % (mem_cgroup.memory.high))
    elif kn.name.endswith(".min"):
        print(" = %d" % (mem_cgroup.memory.min))
    elif kn.name.endswith(".low"):
        print(" = %d" % (mem_cgroup.memory.low))
    elif kn.name.endswith(".current"):
        print(" = %d" % (mem_cgroup.memory.usage.counter * PAGE_SIZE))
    else:
        print("")
    crashcolor.set_color(crashcolor.RESET)



def show_cgroup_value(kn, cgroup, cftype, ss, css):
    crashcolor.set_color(crashcolor.BLUE)
    if kn.name.endswith(".procs"):
        show_cgroup_value_procs(kn, cgroup, cftype, ss, css, False)
    elif kn.name.endswith(".threads"):
        show_cgroup_value_procs(kn, cgroup, cftype, ss, css, True)
    else:
        print("")
    crashcolor.set_color(crashcolor.RESET)
    pass


def show_cgroup_value_procs(kn, cgroup, cftype, ss, css, show_thread):
    first_print = True

    task_offset = member_offset("struct task_struct", "cg_list")
    if ss != None and ss != 0:
        cset_pos = cgroup.e_csets[ss.id]
    else:
        cset_pos = cgroup.cset_links

    for cgrp_cset_link in readSUListFromHead(cset_pos,
                                            'cset_link',
                                            'struct cgrp_cset_link',
                                            maxel=1000000):
        for task in readSUListFromHead(cgrp_cset_link.cset.tasks,
                                        "cg_list",
                                        "struct task_struct",
                                        maxel=1000000):
            if show_thread == False and task.pid != task.tgid:
                continue
            if first_print == True:
                first_print = False
                print(" =", end="")
            print(" %d(%s) " % (task.pid, task.comm), end="")

    print("")


def getKNName(kernfs_node):
    return kernfs_node.name


def show_cgroup2_files(options, cgrp, idx):
    idx_str = "  " * idx + "   * "
    kn_list = []
    for kerndir in for_all_rbtree(cgrp.kn.dir.children,
                                "struct kernfs_node",
                                "rb"):
        try:
            kn = readSU("struct kernfs_node", kerndir)
            kn_list.append(kn)
        except Exception as e:
            print(e)
            pass


    sorted_kn_list = sorted(kn_list, key=getKNName, reverse=False)

    for kn in sorted_kn_list:
        print("%s%s (0x%x)" % (idx_str, kn.name, kn), end="")
        show_cgroup2_file_detail(options, kn, idx)


def getCgroupName(cgroup):
    if len(cgroup.kn.name) == 0:
        return "/"
    return cgroup.kn.name


def show_cgroup2_tree_node(options, cgrp, idx, full_path):
    idx_str = "  " * idx
    cg_name = getCgroupName(cgrp)
    if options.show_detail:
        cg_full_name = full_path + cg_name
    else:
        cg_full_name = cg_name
    print("%s+- %s (0x%x)" % (idx_str, cg_full_name, cgrp))
    if options.show_detail:
        show_cgroup2_files(options, cgrp, idx)

    self_offset = member_offset("struct cgroup", "self")
    cgroup_list = []
    for subsys in readSUListFromHead(cgrp.self.children,
                                    'sibling',
                                    'struct cgroup_subsys_state',
                                    maxel=1000000):
        subcgrp = readSU("struct cgroup", subsys + self_offset)
        cgroup_list.append(subcgrp)

    sorted_cgroup_list = sorted(cgroup_list, key=getCgroupName, reverse=False)

    for subcgrp in sorted_cgroup_list:
        show_cgroup2_tree_node(options, subcgrp, idx + 1,
                full_path + cg_name + ("/" if cg_name != "/" else ""))



def show_cgroup2_tree(options):
    if options.cgroup_addr != "":
        cgroup = readSU("struct cgroup", int(options.cgroup_addr, 16))
    else:
        cgrp_dfl_root = readSymbol("cgrp_dfl_root")
        cgroup = cgrp_dfl_root.cgrp
        
    show_cgroup2_tree_node(options, cgroup, 0, "")
    pass


CGRP_ROOT_CPUSET_V2_MODE=(1<<4)

def show_cgroup_tree(options):
    try:
        cpuset_cgrp_subsys_on_dfl_key = readSymbol("cpuset_cgrp_subsys_on_dfl_key")
        key_enabled = cpuset_cgrp_subsys_on_dfl_key.key.enabled.counter
        cpuset_cgrp_subsys = readSymbol("cpuset_cgrp_subsys")
        subsys_flags = cpuset_cgrp_subsys.root.flags
        if (key_enabled != 0 or
                (subsys_lags & CGRP_ROOT_CPUSET_V2_MODE) == CGRP_ROOT_CPUSET_V2_MODE):
            show_cgroup2_tree(options)
            return
    except Exception as e:
        pass

    try:
        rootnode = readSymbol("rootnode")
        show_cgroup_tree_from_rootnode(rootnode, options)
        return
    except Exception as e:
        pass

    try:
        cgroup_roots = readSymbol("cgroup_roots")
        show_cgroup_tree_from_cgroup_roots(cgroup_roots, options)
        return
    except Exception as e:
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


def get_page_shift():
    resultline = exec_crash_command("ptob 1")
    if len(resultline) == 0:
        return 0

    words = resultline.split()
    if len(words) < 2:
        return 0

    value = int(words[1], 16)
    idx = 0
    while (value > 0):
        value = value >> 1
        idx = idx + 1

    return idx - 1




def print_task_list(idx, cur_cgroup):
    offset = member_offset("struct task_struct", "cg_list")
    print("%stasks = " % ("  " * idx + "   "), end="")

    if member_offset("struct cgroup", "css_sets") >= 0:
        list_start = cur_cgroup.css_sets
        entry_name = "cgrp_link_list"
        struct_name = "struct cg_cgroup_link"
    elif member_offset("struct cgroup", "cset_links") >= 0:
        list_start = cur_cgroup.cset_links
        entry_name = "cset_link"
        struct_name = "struct cgrp_cset_link"
    else:
        return 0

    for cg_link in readSUListFromHead(list_start,
                                      entry_name,
                                      struct_name):

        if struct_name == "struct cg_cgroup_link":
            cg_link_cg = cg_link.cg
        elif struct_name == "struct cgrp_cset_link":
            cg_link_cg = cg_link.cset
        else:
            break

        if cg_link_cg == 0:
            continue
        for task in readSUListFromHead(cg_link_cg.tasks,
                                             "cg_list",
                                             "struct task_struct"):
            print("%d(%s) " % (task.pid, task.comm), end="")
    print("")


def print_mem_cgroup_details(idx, cur_cgroup_subsys_state, cur_cgroup):
    offset = member_offset("struct mem_cgroup", "css")
    if offset < 0:
        return
    idx_str = "  " * idx + "   "
    mem_cgroup = readSU("struct mem_cgroup", cur_cgroup_subsys_state - offset)
    usage_in_bytes = mem_cgroup.memory.count.counter * PAGE_SIZE
    memory_limit_in_bytes = mem_cgroup.memory.limit * PAGE_SIZE
    kmem_limit_in_bytes = mem_cgroup.kmem.limit * PAGE_SIZE
    print("%sstruct mem_cgroup 0x%x" % (idx_str, mem_cgroup))
    print("%smemory.limit_in_bytes = %ld, memory.kmem.limit_in_bytes = %ld" %
          (idx_str, memory_limit_in_bytes, kmem_limit_in_bytes))
    print("%smemory.usage_in_bytes = %ld" %
          (idx_str, usage_in_bytes))


def print_cgroup_details(idx, cur_cgroup):
    for i in range(0, len(cur_cgroup.subsys)):
        if cur_cgroup.subsys[i] != 0:
            subsys = cur_cgroup.subsys[i]
            if cgroup_subsys_id_list[i] == "mem_cgroup_subsys_id":
                print_mem_cgroup_details(idx, cur_cgroup.subsys[i], cur_cgroup)

    print_task_list(idx, cur_cgroup)


def list_empty(list_head):
    return list_head.next == list_head.prev


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

        if (member_offset("struct cgroup_subsys_state", "ss") >= 0):
            subsys_name = addr2sym(subsys.ss)
        else:
            subsys_name =""

        show_entry = True
        if (options.filter_cgroup_name != "" and
                cgroup_name.find(options.filter_cgroup_name) == -1):
            show_entry = False

        if (options.filter_subsys != "" and
                subsys_name.find(options.filter_subsys) == -1):
            show_entry = False

        if (show_entry == True):
            print ("%s%s%s at 0x%x (%d) // %s" %
                   ("  " * idx, "+--" if idx > 0 else "",
                    cgroup_name, cgroup, cgroup_counter, subsys_name))
            if options.show_detail:
                print_cgroup_details(idx, cgroup)

            if options.task_list:
                cgroup_task_list(cgroup, idx)


        head_of_list = None
        if member_offset("struct cgroup", "children") > -1:
            head_of_list = cgroup.children
            struct_name = "struct cgroup"
        elif member_offset("struct cgroup_subsys_state", "children") > -1:
            head_of_list = cgroup.self.children
            struct_name = "struct cgroup_subsys_state"

        for childaddr in readSUListFromHead(head_of_list,
                                            'sibling', struct_name,
                                            maxel=1000000):
            has_child = True
            if struct_name == "struct cgroup":
                cgroup = readSU(struct_name, childaddr)
            else:
                subsys_state = readSU(struct_name, childaddr)
                cgroup = subsys_state.cgroup
                if list_empty(subsys_state.children):
                    has_child = False

            if has_child == True:
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
    if idr_layer == 0:
        return

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


idr_max = 65534

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


    print("\nTotal allocated count = %d out of %d" %
          (total_count, idr_max))


def cgroupinfo():
    global empty_count
    global cgroup_count
    global PAGE_SIZE

    op = OptionParser()
    op.add_option("-c", "--cgroup", dest="cgroup_addr", default="",
                  action="store", type="string",
                  help="Shows a speicific cgroup tree")

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

    op.add_option("-n", "--name", dest="filter_cgroup_name", default="",
                  action="store", type="string",
                  help="Shows cgroups with specified name only")

    op.add_option("-s", "--subsys", dest="filter_subsys", default="",
                  action="store", type="string",
                  help="Shows cgroups with specified subsystem only")
    (o, args) = op.parse_args()

    sys.setrecursionlimit(10**6)

    cgroup_count = 0
    empty_count = 0
    cgroup_subsys_id_init()
    #PAGE_SIZE = 1 << get_page_shift()
    PAGE_SIZE=crash.PAGESIZE

    if (o.mem_cgroup_idr or o.mem_cgroup_idr_all):
        show_mem_cgroup_idr(o)
        sys.exit(0)

    if (o.taskgroup_list):
        show_task_group(o)
        sys.exit(0)

    # default is showing tree
    show_cgroup_tree(o)


if ( __name__ == '__main__'):
    check_global_symbols()
    cgroupinfo()
