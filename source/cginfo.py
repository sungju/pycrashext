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
        help_s_out = exec_crash_command("help -m")
        lines = help_s_out.splitlines()
        for line in lines:
            words = line.split(":")
            if words[0].strip() == "kvbase":
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
    elif ss_name == "pids":
        show_pids_value(kernfs_node, cgroup, cftype, ss, css)
    elif ss_name.startswith("cgroup."):
        show_cgroup_value(kernfs_node, cgroup, cftype, ss, css)
    else:
        print("")
        print("%s%s (0x%x)" % (idx_str, ss_name, css))

    #print(cftype)


def show_pids_value(kn, cgroup, cftype, ss, css):
    css_offset = member_offset("struct pids_cgroup", "css")
    pids_cgroup = readSU("struct pids_cgroup", css - css_offset)
    crashcolor.set_color(crashcolor.BLUE)
    if kn.name.endswith(".current"):
        print(" = %d" % (pids_cgroup.counter.counter))
    elif kn.name.endswith(".events"):
        print(" = max %d" % (pids_cgroup.events_limit.counter))
    elif kn.name.endswith(".max"):
        print(" = %d" % (pids_cgroup.limit.counter))
    else:
        print("%s (0x%x)" % (ss_name, css))
    crashcolor.set_color(crashcolor.RESET)


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
        

MEMCG_LOW = 0
MEMCG_HIGH = 1
MEMCG_MAX = 2
MEMCG_OOM = 3
MEMCG_OOM_KILL = 4
MEMCG_SWAP_HIGH = 5
MEMCG_SWAP_MAX = 6
MEMCG_SWAP_FAIL = 7

def get_memory_events(events):
    result = "low %d, high = %d, max = %d, oom = %d, oom_kill = %d" %\
            (events[MEMCG_LOW].counter,
             events[MEMCG_HIGH].counter,
             events[MEMCG_MAX].counter,
             events[MEMCG_OOM].counter,
             events[MEMCG_OOM_KILL].counter)
    return result


def get_memory_swap_events(events):
    result = "high = %d, max = %d, fail = %d" %\
            (events[MEMCG_SWAP_HIGH].counter,
             events[MEMCG_SWAP_MAX].counter,
             events[MEMCG_SWAP_FAIL].counter)
    return result


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
    elif kn.name.endswith(".oom.group"):
        print(" = %d" % (mem_cgroup.oom_group))
    elif kn.name.endswith("memory.events"):
        print(" = %s" % (get_memory_events(mem_cgroup.memory_events)))
    elif kn.name.endswith("memory.events.local"):
        print(" = %s" % (get_memory_events(mem_cgroup.memory_events_local)))
    elif kn.name.endswith("swap.events"):
        print(" = %s" % (get_memory_swap_events(mem_cgroup.memory_events)))
    elif kn.name.endswith("memory.numa_stat"):
        print("") # memory_numa_stat_show()
    elif kn.name.endswith("memory.stat"):
        print("") # memory_stat_format(mem_cgroup)
    elif kn.name.endswith(".pressure"):
        print(cftype)
    else:
        print("")
    crashcolor.set_color(crashcolor.RESET)


def cgroup_is_populated(cgroup):
    popcnt = cgroup.nr_populated_csets + \
            cgroup.nr_populated_domain_children +\
            cgroup.nr_populated_threaded_children
    return (1 if popcnt > 0 else 0)


def get_cgroup_events(cgroup):
    result = "populated %d, frozen %d" % \
            (cgroup_is_populated(cgroup),
             1 if (cgroup.flags & CGRP_FROZEN) == CGRP_FROZEN else 0)
    return result


def cgroup_is_threaded(cgroup):
    return cgroup.dom_cgrp != cgroup


def cgroup_parent(cgrp):
    parent_css = cgrp.self.parent
    css_offset = member_offset("struct cgroup", "self")
    if parent_css != 0 and parent_css != None:
        return readSU("struct cgroup", parent_css - css_offset)

    return None


def cgroup_has_tasks(cgroup):
    return cgroup.nr_populated_csets > 0


def cgroup_is_thread_root(cgroup):
    if cgroup_is_threaded(cgroup):
        return False

    if cgroup.nr_threaded_children:
        return True

    cgrp_dfl_threaded_ss_mask = readSymbol("cgrp_dfl_threaded_ss_mask")

    if cgroup_has_tasks(cgroup) and \
        (cgroup.subtree_control & cgrp_dfl_threaded_ss_mask):
        return True

    return False


def cgroup_is_mixable(cgroup):
    return cgroup_parent(cgroup) == None


def cgroup_is_valid_domain(cgroup):
    if cgroup_is_threaded(cgroup):
        return False

    cgroup = cgroup_parent(cgroup)
    while cgroup != None:
        if (not cgroup_is_mixable(cgroup) and cgroup_is_thread_root(cgroup)):
            return False
        if cgroup_is_threaded(cgroup):
            return False

        cgroup = cgroup_parent(cgroup)

    return True


def get_cgroup_type(cgroup):
    if cgroup_is_threaded(cgroup):
        return "threaded"
    elif not cgroup_is_valid_domain(cgroup):
        return "domain invalid"
    elif cgroup_is_thread_root(cgroup):
        return "domain threaded"
    else:
        return "domain"


def get_subtree_control(ss_mask):
    cgroup_subsys = readSymbol("cgroup_subsys")
    idx = 0
    result = ""
    while ss_mask != 0:
        if (ss_mask & 0x1) == 0x1:
            result = result + ("%s " % (cgroup_subsys[idx].name))
        idx = idx + 1
        ss_mask = ss_mask >> 1

    return result


def cgroup_on_dfl(cgroup):
    cgrp_dfl_root = readSymbol("cgrp_dfl_root")
    return cgroup.root == cgrp_dfl_root


def get_cgroup_parent(cgroup):
    parent_css = cgroup.self.parent
    if parent_css != None and Addr(parent_css) >= first_ksymbol:
        css_offset = member_offset("struct cgroup", "self")
        return readSU("struct cgroup", parent_css - css_offset)

    return None


def get_cgroup_control(cgroup):
    parent = get_cgroup_parent(cgroup)
    root_ss_mask = cgroup.root.subsys_mask
    cgrp_dfl_threaded_ss_mask = readSymbol("cgrp_dfl_threaded_ss_mask")
    cgrp_dfl_implicit_ss_mask = readSymbol("cgrp_dfl_implicit_ss_mask")
    if parent != None:
        ss_mask = parent.subtree_control
        if cgroup_is_threaded(cgroup):
            ss_mask = ss_mask & cgrp_dfl_threaded_ss_mask
        return ss_mask

    if cgroup_on_dfl(cgroup):
        root_ss_mask = root_ss_mask & ~(cgrp_dfl_threaded_ss_mask | cgrp_dfl_implicit_ss_mask)

    return root_ss_mask


def show_cgroup_value(kn, cgroup, cftype, ss, css):
    crashcolor.set_color(crashcolor.BLUE)
    if kn.name.endswith(".procs"):
        show_cgroup_value_procs(kn, cgroup, cftype, ss, css, False)
    elif kn.name.endswith(".threads"):
        show_cgroup_value_procs(kn, cgroup, cftype, ss, css, True)
    elif kn.name.endswith(".controllers"):
        print(" = %s" % (get_subtree_control(get_cgroup_control(cgroup))))
    elif kn.name.endswith(".events"):
        print(" = %s" % (get_cgroup_events(cgroup)))
    elif kn.name.endswith(".freeze"):
        print(" = %d" % (cgroup.freezer.freeze))
    elif kn.name.endswith(".kill"):
        print("") # Write-Only file
    elif kn.name.endswith(".max.depth"):
        print(" = %d" % (cgroup.max_depth))
    elif kn.name.endswith(".max.descendants"):
        print(" = %d" % (cgroup.max_descendants))
    elif kn.name.endswith(".subtree_control"):
        print(" = %s" % (get_subtree_control(cgroup.subtree_control)))
    elif kn.name.endswith("cgroup.type"):
        print(" = %s" % (get_cgroup_type(cgroup)))
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
        #print(e)
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
    if options.cgroup_addr != "":
        top_cgroup = readSU("struct cgroup", int(options.cgroup_addr, 16))

    print_cgroup_entry(top_cgroup, top_cgroup, 0, options)
    sys.setrecursionlimit(curlimit)
    print ("-" * 70)
    crashcolor.set_color(crashcolor.BLUE)
    print ("Total number of cgroup(s) = %d, %d had 0 count" %
           (cgroup_count, empty_count))
    crashcolor.set_color(crashcolor.RESET)


def show_cgroup_sub_tree(options):
    try:
        cgroup = readSU("struct cgroup", int(options.cgroup_addr, 16))
        show_cgroup_tree_entry(options, cgroup, 0)
    except Exception as e:
        print(e)

def get_atomic_count(count):
    counter = count.counter
    return counter


def get_atomic_count_str(count, size=64):
    counter = get_atomic_count(count)
    if counter < 0:
        if size == 64:
            return "0x%x" % (counter & 0xffffffffffffffff)
        elif size == 32:
            return "0x%x" % (counter & 0xffffffff)
        else:
            return "0x%x" % (counter)


    return "%d" % counter


CSS_NO_REF = (1 << 0)
CSS_ONLINE = (1 << 1)
CSS_RELEASED = (1 << 2)
CSS_VISIBLE = (1 << 3)
CSS_DYING = (1 << 4)

def get_css_flags_str(css):
    if css == 0:
        return ""
    str = ""
    if css.flags & CSS_NO_REF:
        str = str + "CSS_NO_REF "
    if css.flags & CSS_ONLINE:
        str = str + "CSS_ONLINE "
    if css.flags & CSS_RELEASED:
        str = str + "CSS_RELEASED "
    if css.flags & CSS_VISIBLE:
        str = str + "CSS_VISIBLE "
    if css.flags & CSS_DYING:
        str = str + "CSS_DYING "

    return str.strip()


__PERCPU_REF_ATOMIC = 1 << 0
__PERCPU_REF_DEAD = 1 << 1
__PERCPU_REF_ATOMIC_DEAD = __PERCPU_REF_ATOMIC | __PERCPU_REF_DEAD
__PERCPU_REF_FLAG_BITS = 2

def get_percpu_count_str(percpu_ref):
#    count = percpu_ref.percpu_count_ptr & ~__PERCPU_REF_ATOMIC_DEAD
#    if count == 0:
#        return ""
#    else:
#        return "__PERCPU_REF_ATOMIC_DEAD"
    if percpu_ref.percpu_count_ptr & __PERCPU_REF_ATOMIC_DEAD:
        return "__PERCPU_REF_ATOMIC_DEAD"
    elif percpu_ref.percpu_count_ptr & __PERCPU_REF_ATOMIC:
        return "__PERCPU_REF_ATOMIC"
    elif percpu_ref.percpu_count_ptr & __PERCPU_REF_DEAD:
        return "__PERCPU_REF_DEAD"
    else:
        return ""


CGRP_NOTIFY_ON_RELEASE = 1 << 0
CGRP_CPUSET_CLONE_CHILDREN = 1 << 1
CGRP_FREEZE = 1 << 2
CGRP_FROZEN = 1 << 3

def get_cgrp_flags_str(cgroup):
    result_str = ""
    if cgroup.flags & CGRP_NOTIFY_ON_RELEASE:
        result_str = result_str + "CGRP_NOTIFY_ON_RELEASE "
    if cgroup.flags & CGRP_CPUSET_CLONE_CHILDREN:
        result_str = result_str + "CGRP_CPUSET_CLONE_CHILDREN "
    if cgroup.flags & CGRP_FREEZE:
        result_str = result_str + "CGRP_FREEZE "
    if cgroup.flags & CGRP_FROZEN:
        result_str = result_str + "CGRP_FROZEN "

    return result_str.strip()


def get_subsys_str(subsys_addr):
    if subsys_addr == 0:
        return ""
    subsys = readSU("struct cgroup_subsys_state", subsys_addr)
    return get_subsys_name(subsys)


def show_cgroup_tree_entry(options, cgroup, idx):
    global empty_count
    global cgroup_count
    global dead_count

    subsys_name_list = ""
    for subsys_addr in cgroup.subsys:
        subsys_name_list = subsys_name_list + get_subsys_str(subsys_addr) + " "
    subsys_name_list = subsys_name_list.strip()

    cgroup_count = cgroup_count + 1
    cgroup_counter = cgroup_task_count(cgroup)
    if cgroup_counter == 0:
        empty_count = empty_count + 1
        crashcolor.set_color(crashcolor.RED)
    else:
        crashcolor.set_color(crashcolor.RESET)

    refcount = get_atomic_count_str(cgroup.self.refcnt.count)
    flags_str = get_cgrp_flags_str(cgroup)
    css_flags_str = get_css_flags_str(cgroup.self)
    bpf_refcount = get_atomic_count_str(cgroup.bpf.refcnt.count)

    if member_offset("struct cgroup", "nr_dying_descendants") >= 0:
        nr_dying_str = "  nr_dying_descendants = %d," % cgroup.nr_dying_descendants
    else:
        nr_dying_str = ""

    if member_offset("struct percpu_ref ", "percpu_count_ptr") >= 0:
        percpu_count_str = get_percpu_count_str(cgroup.self.refcnt)
        if percpu_count_str.find("DEAD") >= 0:
            dead_count = dead_count + 1
    else:
        percpu_count_str = "" # This needs to be changed later for percpu_ref.data implementation


    pids_max = ""
    events_limit = ""
#    if member_offset("struct pids_cgroup", "css") >= 0:
#        pids_cgroup = readSU("struct pids_cgroup", cgroup.self)
#        pids_max = ", pids.max = %s" % (get_atomic_count_str(pids_cgroup.limit))
#        events_limit = ", fork failed count = %s" % (get_atomic_count_str(pids_cgroup.events_limit))

    print("%s* %s %s %s %s" % \
          ("\t" * idx, get_cgroup_name(cgroup), cgroup, subsys_name_list,flags_str))
    print("%s%s refcnt.count = %s, bpf.refcnt.count = %s, %s%s%s %s" % \
            ("\t" * idx, nr_dying_str, refcount, bpf_refcount, percpu_count_str, pids_max, events_limit,
             css_flags_str))

    crashcolor.set_color(crashcolor.RESET)
    if options.show_detail:
        print_cgroup_details(idx, cgroup)

    try:
        idx = idx + 1
        first = cgroup.self.children
        for css in readSUListFromHead(first,
                                     'sibling',
                                     'struct cgroup_subsys_state',
                                     inchead = False):
            cg = readSU("struct cgroup", css)
            if cg == cgroup:
                continue
            show_cgroup_tree_entry(options, cg, idx)
    except Exception as e:
        print(e)
    return


def show_cgroup_tree_from_cgroup_roots(cgroup_roots, options):
    global empty_count
    global cgroup_count
    global dead_count

    empty_count = 0
    cgroup_count = 0
    dead_count = 0

    crashcolor.set_color(crashcolor.BLUE)
    crashcolor.set_color(crashcolor.RESET)
    if options.cgroup_addr:
        print ("** cgroup sub-tree for %s **" % options.cgroup_addr)
        show_cgroup_sub_tree(options)
        return
    else:
        print ("** cgroup tree **")
        cgroup_root_list = cgroup_roots

    for cgroup_root in readSUListFromHead(cgroup_roots,
                                          'root_list',
                                          'struct cgroup_root',
                                          maxel=1000000):
        top_cgroup = cgroup_root.cgrp
        curlimit = sys.getrecursionlimit()
        sys.setrecursionlimit(1000)
        show_cgroup_tree_entry(options, top_cgroup, 0)
        #print_cgroup_entry(top_cgroup, top_cgroup, 0, options)
        sys.setrecursionlimit(curlimit)

    print ("-" * 70)
    crashcolor.set_color(crashcolor.BLUE)
    print ("Total number of cgroup(s) = %d, %d had 0 count, %d cgroups in *_DEAD state" %
            (cgroup_count, empty_count, dead_count))
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
    print("%s  - tasks = <" % ("\t" * idx + " "), end="")

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
                                      struct_name,
                                      maxel=1000000):

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
                                       "struct task_struct",
                                       maxel=1000000):
            print("%d(%s) " % (task.pid, task.comm), end="")
    print(">")


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


def print_cset_links(idx, cgroup):
    for cgrp_cset_link in readSUListFromHead(cgroup.cset_links,
                                             'cset_link', "struct cgrp_cset_link",
                                        maxel=1000000):
        cset = cgrp_cset_link.cset
        refcount = get_atomic_count_str(cset.refcount.refs, 32)
        print("%s   - %s %s" % ("\t"*idx, cgrp_cset_link, cset))
        print("%s      cset.refcnt=%s,cset.dead=%d" % ("\t"*idx, refcount, cset.dead))
''' Unnecessary as it is immutable since system boot
        for subsys_addr in cset.subsys:
            print("%s\t%s, %s" % ("\t"*idx, get_subsys_str(subsys_addr),
                                 get_css_flags_str(subsys_addr)))
'''


def print_cgroup_details(idx, cur_cgroup):
    for i in range(0, len(cur_cgroup.subsys)):
        if cur_cgroup.subsys[i] != 0:
            subsys = cur_cgroup.subsys[i]
            if cgroup_subsys_id_list[i] == "mem_cgroup_subsys_id":
                print_mem_cgroup_details(idx, cur_cgroup.subsys[i], cur_cgroup)

    print_cset_links(idx, cur_cgroup)
    print_task_list(idx, cur_cgroup)


def list_empty(list_head):
    return list_head.next.next == list_head.next


def get_cgroup_name(cgroup):
    cgroup_name = ""
    if member_offset("struct cgroup", "dentry") > -1:
        if (cgroup.dentry != 0):
            cgroup_name = dentry_to_filename(cgroup.dentry)
    elif member_offset("struct cgroup", "kn") > -1:
        cgroup_name = cgroup.kn.name

    if cgroup_name == "":
        cgroup_name = "/"

    return cgroup_name


def get_subsys_name(subsys):
    if (member_offset("struct cgroup_subsys_state", "ss") >= 0):
        if subsys.ss:
            subsys_name = addr2sym(subsys.ss)
        else:
            subsys_name = ""
    else:
        subsys_name =""

    return subsys_name


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
        cgroup_name = get_cgroup_name(cgroup)
        cgroup_counter = cgroup_task_count(cgroup)

        if cgroup_counter == 0:
            crashcolor.set_color(crashcolor.RED)
            e_count = 1
        else:
            crashcolor.set_color(crashcolor.RESET)

        subsys_name = get_subsys_name(subsys)

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

    try:
        root_task_group = readSymbol("root_task_group")
        (count, empty_count) = show_task_group_tree(options, root_task_group)
    except: # if root_task_group does not work
        count = 0
        empty_count = 0
        for task_group in readSUListFromHead(sym2addr('task_groups'),
                                             'list', 'struct task_group',
                                             maxel=1000000):
            (tg_count, tg_empty_count) = show_task_group_detail(options, task_group)
            count = count + tg_count
            empty_count = empty_count + tg_empty_count

    print ("-" * 70)
    crashcolor.set_color(crashcolor.BLUE)
    print ("Total number of task_group(s) = %d, %d had 0 count" %
           (count, empty_count))
    crashcolor.set_color(crashcolor.RESET)


def show_task_group_detail(options, task_group, indent=0):
    count = 0
    empty_count = 0

    css = readSU('struct cgroup_subsys_state', task_group.css)
    if (css == 0):
        return (0, 0)
    if (css.cgroup == 0):
        return (0, 0)
    cgroup = readSU('struct cgroup', css.cgroup)
    if (cgroup == 0):
        return (0, 0)
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


    ss_name = ""
    try:
        ss_name = exec_crash_command("sym %x" % (task_group.css.ss)).split()[-1]
    except:
        pass

    if member_offset("struct cgroup", "nr_dying_descendants") >= 0:
        nr_dying_str = ", nr_dying_descendants = %d" % cgroup.nr_dying_descendants
    else:
        nr_dying_str = ""


    indent_str = "\t" * indent
    print ("%stask_group = 0x%x, cgroup = 0x%x, counter=%d\n" \
           "%s (%s, %s)%s" % \
            (indent_str, task_group, cgroup, cgroup_counter,\
             indent_str, cgroup_name, ss_name, nr_dying_str))
    if options.show_detail:
        cgroup_details(task_group, cgroup, 0)

    if options.task_list:
        cgroup_task_list(cgroup, 0)

    crashcolor.set_color(crashcolor.RESET)
    return (count, empty_count)


def show_task_group_tree(options, task_group=None, indent=0):
    if task_group == None:
        task_group = readSU("struct task_group", int(options.taskgroup_tree, 16))
    (count, empty_count) = show_task_group_detail(options, task_group, indent)
    for task_group in readSUListFromHead(task_group.children,
                                         'siblings', 'struct task_group',
                                         maxel=1000000):
        (tg_count, tg_empty_count) = show_task_group_tree(options, task_group, indent+1)
        count = count + tg_count
        empty_count = empty_count + tg_empty_count

    return (count, empty_count)

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

    op.add_option("-d", "--detail", dest="show_detail", default=0,
                  action="store_true",
                  help="Shows cgroup details")

    op.add_option("-g", "--tglist", dest="taskgroup_list", default=0,
                  action="store_true",
                  help="task_group list")

    op.add_option("-G", "--tgtree", dest="taskgroup_tree", default="",
                  action="store", type="string",
                  help="task_group tree")

    op.add_option("-i", "--idr", dest="mem_cgroup_idr", default=0,
                  action="store_true",
                  help="mem_cgroup_idr detail")

    op.add_option("-I", "--IDR", dest="mem_cgroup_idr_all", default=0,
                  action="store_true",
                  help="mem_cgroup_idr detail include free entries")

    op.add_option("-l", "--tasklist", dest="task_list", default=0,
                  action="store_true",
                  help="Shows task list in cgroup")

    op.add_option("-n", "--name", dest="filter_cgroup_name", default="",
                  action="store", type="string",
                  help="Shows cgroups with specified name only")

    op.add_option("-s", "--subsys", dest="filter_subsys", default="",
                  action="store", type="string",
                  help="Shows cgroups with specified subsystem only")

    op.add_option("-t", "--tree", dest="cgroup_tree", default=0,
                  action="store_true",
                  help="hierarchial display of cgroups")

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

    if (o.taskgroup_tree != ""):
        show_task_group_tree(o)
        sys.exit(0)

    # default is showing tree
    show_cgroup_tree(o)


if ( __name__ == '__main__'):
    check_global_symbols()
    cgroupinfo()
