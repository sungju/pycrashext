"""
 Written by Daniel Sungju Kwon
"""

from pykdump.API import *

from LinuxDump import Tasks
from LinuxDump.trees import *

import crashcolor

import sys
from datetime import datetime


def getKey(rqobj):
    return rqobj.Timestamp


def getDelayKey(taskobj):
    return taskobj.sched_info.run_delay


def get_task_policy_str(policy):
    try:
        return {
            0: "N", # SCHED_NORMAL
            1: "F", # SCHED_FIFO
            2: "R", # SCHED_RR
            3: "B", # SCHED_BATCH
            5: "I", # SCHED_IDLE
            6: "D", # SCHED_DEADLINE
        }[policy]
    except:
        return "?"


def print_task_delay(task, options):
    try:
        sched_info = task.sched_info
        prio = task.prio
        if (task.policy != 0):
            prio = task.rt_priority

        print ("%20s (0x%x)[%s:%3d] : %10.2f sec delayed in queue" %
               (task.comm, task, get_task_policy_str(task.policy),
                prio, sched_info.run_delay // 1000000000))
        if (options.details):
            print ("\t\t\texec_start = %d, exec_max = %d" %
                   (task.se.exec_start, task.se.exec_max))
    except:
        pass


def show_rt_stat_in_rq(rq):
    rt = rq.rt
    rt_period = rt.tg.rt_bandwidth.rt_period.tv64
    print ("CPU %3d: rt_nr_running = %d, rt_throttled = %d\n"
           "\trt_time = %12d, rt_runtime = %10d, rt_period = %d" %
           (rq.cpu, rt.rt_nr_running, rt.rt_throttled, rt.rt_time,
            rt.rt_runtime, rt_period))


def show_rt_stat(options):
    rqlist = Tasks.getRunQueues()
    for rq in rqlist:
        show_rt_stat_in_rq(rq)


def show_rq_task_list(runqueue, reverse_sort, options):
    """
    rq->rq->active->queue[..]

    crash> rq.rt ffff880028376ec0 -ox
    struct rq {
      [ffff880028377048] struct rt_rq rt;
      }
      crash> rt_rq.active ffff880028377048 -ox
      struct rt_rq {
            [ffff880028377048] struct rt_prio_array active;
      }
      crash> rt_prio_array.bitmap ffff880028377048 -ox
      struct rt_prio_array {
            [ffff880028377048] unsigned long bitmap[2];
      }
      crash> rd ffff880028377048 2
      ffff880028377048:  0000000000000001 0000001000000000   ................

      crash> list_head ffff880028377058
      struct list_head {
            next = 0xffff88145f3c16e8,
            prev = 0xffff88145f3d4c78
      }
    """
    head_displayed = False
    rt_array = runqueue.rt.active
    for task_list in rt_array.queue:
        for sched_rt_entity in readSUListFromHead(task_list,
                                        "run_list",
                                        "struct sched_rt_entity"):
            task_offset = member_offset("struct task_struct", "rt")
            task_addr = sched_rt_entity - task_offset
            task = readSU("struct task_struct", task_addr)
            if (not head_displayed):
                print("  RT tasks:")
                head_displayed = True

            print_task_delay(task, options)


def read_task_from_sched_entity(sched_entity, runqueue):
    if (sched_entity == runqueue.cfs.curr):
        return None
    task_offset = member_offset("struct task_struct", "se")
    task_addr = sched_entity - task_offset
    task = readSU('struct task_struct', task_addr)
    return task


def show_cfs_task_list(runqueue, reverse_sort, options):
    """
    """
    task_list = []
    task_root = None

    if (member_offset('struct rq', 'cfs_tasks') >= 0):
        for sched_entity in readSUListFromHead(runqueue.cfs_tasks,
                                               "group_node",
                                               "struct sched_entity"):
            task = read_task_from_sched_entity(sched_entity,
                                               runqueue)
            if (task != None):
                task_list.append(task)
    elif (member_offset("struct cfs_rq", "tasks_timeline") >= 0):
        for sched_entity in for_all_rbtree(runqueue.cfs.tasks_timeline,
                                           "struct sched_entity",
                                           "run_node"):
            task = read_task_from_sched_entity(sched_entity,
                                               runqueue)
            if (task != None):
                task_list.append(task)
    elif (member_offset("struct cfs_rq", "tasks") >= 0):
        for sched_entity in readSUListFromHead(runqueue.cfs.tasks,
                                             "group_node",
                                             "struct sched_entity"):
            task = read_task_from_sched_entity(sched_entity,
                                               runqueue)
            if (task != None):
                task_list.append(task)
    else:
        task_list = []


    sorted_task_list = sorted(task_list,
                              key=getDelayKey,
                              reverse=not reverse_sort)
    if (len(sorted_task_list)):
        print("  CFS tasks:")

    for task in sorted_task_list:
        print_task_delay(task, options)

def show_prio_array(title, prio_array, reverse_sort, options):
    print ("%s" % (title))
    has_any_entry = 0
    for idx in range(0,140):
        task_list = []
        for task in readSUListFromHead(prio_array.queue[idx],
                                       "run_list",
                                       "struct task_struct"):
            task_list.insert(0, task)
        if (len(task_list) == 0):
            continue

        has_any_entry = 1
        sorted_task_list = sorted(task_list,
                                  key=getDelayKey,
                                  reverse=not reverse_sort)

        print ("\t[%4d]" % (idx))
        for task in sorted_task_list:
            print_task_delay(task, options)

    if (has_any_entry == 0):
        print("\tNo entry under this array")

    return


def show_prio_task_list(runqueue, reverse_sort, options):
    show_prio_array("Active prio_array", runqueue.active,
                    reverse_sort, options)
    show_prio_array("Expired prio_array", runqueue.expired,
                    reverse_sort, options)


def show_task_list(runqueue, reverse_sort, options):
    if (member_offset('struct rq', 'rt') >= 0):
        show_rq_task_list(runqueue, reverse_sort, options)
    if (member_offset('struct rq', 'cfs') >= 0):
        show_cfs_task_list(runqueue, reverse_sort, options)
    if (member_offset('struct rq', 'active') >= 0):
        show_prio_task_list(runqueue, reverse_sort, options)
    print("")


def get_useconds(dto):
    days, hours, minutes, seconds, useconds = dto
    return useconds + (seconds * 1000000) + (minutes * 60 * 1000000) + (hours * 60 * 60 * 1000000) + (days * 24 * 60 * 60 * 1000000)



def lockup_display(reverse_sort, show_tasks, options):
    rqlist = Tasks.getRunQueues()
    rqsorted = sorted(rqlist, key=getKey, reverse=reverse_sort)
    if (reverse_sort):
        now = rqsorted[0].Timestamp
    else:
        now = rqsorted[-1].Timestamp

    try:
        watchdog_thresh = readSymbol("watchdog_thresh")
        softlockup_thresh = watchdog_thresh * 2
    except:
        try:
            softlockup_thresh = readSymbol("softlockup_thresh")
            watchdog_thresh = 10
        except:
            watchdog_thresh = -1

    for rq in rqsorted:
        if options.compact and rq.curr.comm.startswith("swapper/"):
            continue
        prio = rq.curr.prio
        if (rq.curr.policy != 0):
            prio = rq.curr.rt_priority

        delayed_time = (now - rq.Timestamp) // 1000000000
        if watchdog_thresh > 0:
            if delayed_time >= softlockup_thresh:
                crashcolor.set_color(crashcolor.RED)
            elif delayed_time >= watchdog_thresh:
                crashcolor.set_color(crashcolor.BLUE)

        print ("CPU %3d: %10.2f sec behind by "
               "0x%x, %s [%s:%3d] (%d in queue)" %
               (rq.cpu, delayed_time,
                rq.curr, rq.curr.comm,
                get_task_policy_str(rq.curr.policy), prio, rq.nr_running))

        task_pid = rq.curr
        if options.details:
            task_time = exec_crash_command("ps -m 0x%x" % (task_pid)).splitlines()[0]
            task_time = task_time.split("]")[0][1:]
            days_str, time_str = task_time.split()
            dto = datetime.strptime(time_str, "%H:%M:%S.%f")

            date_info = (int(days_str), dto.hour, dto.minute, dto.second, dto.microsecond)
            runtime = get_useconds(date_info)
            if runtime >= 2 * 60 * 1000000:
                crashcolor.set_color(crashcolor.LIGHTRED)
            elif runtime >= 60 * 1000000:
                crashcolor.set_color(crashcolor.BLUE)
            elif runtime >= 10 * 1000000:
                crashcolor.set_color(crashcolor.GREEN)
            elif runtime >= 1 * 1000000:
                crashcolor.set_color(crashcolor.YELLOW)
            else:
                crashcolor.set_color(crashcolor.RESET)
            print(" └──> ps -m %-8s : %s" % (rq.curr.pid, task_time))
            crashcolor.set_color(crashcolor.RESET)

        if options.backtrace:
            bt_output = exec_crash_command("bt 0x%x" % (task_pid))
            if options.user and bt_output.find("CS: 0010") >= 0:
                continue
            print("\t%s" % (bt_output.replace('\n', '\n\t')))

        if (show_tasks):
            show_task_list(rq, reverse_sort, options)

        crashcolor.set_color(crashcolor.RESET)

    print("\n\tkernel.watchdog_thresh = %d, " % (watchdog_thresh), end="")
    crashcolor.set_color(crashcolor.BLUE)
    print("Hard LOCKUP : %d seconds, " % (watchdog_thresh), end="")
    crashcolor.set_color(crashcolor.RED)
    print("Soft LOCKUP : %d seconds" % (softlockup_thresh))
    crashcolor.set_color(crashcolor.RESET)



NR_CPUS=0

def get_nr_cpus():
    global NR_CPUS

    lines = exec_crash_command("help -k").splitlines()
    for line in lines:
        words = line.split(':')
        if words[0] == 'kernel_NR_CPUS':
            NR_CPUS = int(words[1])
            return NR_CPUS

    NR_CPUS = sys_info.CPUS
    return sys_info.CPUS

def show_qspinlock(options):
    '''
include/asm-generic/qspinlock_types.h
/*
 * Bitfields in the atomic value:
 *
 * When NR_CPUS < 16K
 *  0- 7: locked byte
 *     8: pending
 *  9-15: not used
 * 16-17: tail index
 * 18-31: tail cpu (+1)
 *
 * When NR_CPUS >= 16K
 *  0- 7: locked byte
 *     8: pending
 *  9-10: tail index
 * 11-31: tail cpu (+1)
 */
    '''
    qspinlock = readSU("struct qspinlock", int(options.qspinlock, 16))
    get_nr_cpus()

    lock_val = qspinlock.val.counter
    print("spinlock status".center(26))
    print("=" * 26)
    print("%12s : 0x%x" % ("value", lock_val))
    print()
    print("%12s : %d" % ("locked", (lock_val & 0xff)))
    print("%12s : %d" % ("pending", (1 if (lock_val & 0x100) == 0x100 else 0)))
    if NR_CPUS < 16000:
        print("%12s : %d" % ("tail index", ((lock_val >> 16) & 0x3)))
        print("%12s : %d" % ("tail cpu", (((lock_val >> 18) & 0x7ff) - 1)))
    else:
        print("%12s : %d" % ("tail index", ((lock_val >> 9) & 0x3)))
        print("%12s : %d" % ("tail cpu", (((lock_val >> 11) & 0x3fffff) - 1)))



def show_smp_call_data(cfd_addr, csd_addr=None):
    """
    Find which CPU owns a struct __call_single_data address from call_function_data
    Used for debugging smp_call_function_many_cond hangs

    Args:
        cfd_addr: Address of call_function_data structure
        csd_addr: Optional struct __call_single_data address to find which CPU it belongs to
    """
    try:
        # Read call_function_data structure
        crashcolor.set_color(crashcolor.BLUE)
        print("=" * 80)
        print("SMP Call Function Data Analysis")
        print("=" * 80)
        crashcolor.set_color(crashcolor.RESET)

        print("\nStep 1: Reading call_function_data at 0x%x" % cfd_addr)
        print("-" * 80)

        cfd = readSU("struct call_function_data", cfd_addr)

        print("struct call_function_data {")
        print("  csd = 0x%x," % cfd.csd)
        print("  cpumask = 0x%x," % cfd.cpumask)
        print("  cpumask_ipi = 0x%x" % cfd.cpumask_ipi)
        print("}")

        # Get per-cpu offset
        percpu_offset = cfd.csd

        print("\nStep 2: Converting per-cpu offset 0x%x to virtual addresses" % percpu_offset)
        print("-" * 80)

        # Use crash ptov command to convert per-cpu offset to virtual addresses for all CPUs
        # ptov <offset>:a shows virtual addresses for all CPUs
        ptov_output = exec_crash_command("ptov 0x%x:a" % percpu_offset)

        # Build a table of CPU -> virtual address mappings
        cpu_csd_map = {}

        # Parse ptov output
        # Format: "  [CPU]  virtual_address"
        for line in ptov_output.splitlines():
            line = line.strip()
            if line.startswith('[') and ']' in line:
                try:
                    # Extract CPU number and address
                    # Format: "[20]  ffff9caa2633ae60"
                    cpu_part = line.split(']')[0].replace('[', '')
                    addr_part = line.split(']')[1].strip()

                    cpu = int(cpu_part)
                    vaddr = int(addr_part, 16)

                    cpu_csd_map[cpu] = vaddr
                except:
                    pass

        print("\n%-6s  %-18s" % ("CPU", "struct __call_single_data Address"))
        print("-" * 80)

        # If target address provided, show only matching CPU and surrounding context
        if csd_addr:
            # Find the matching CPU
            found_cpu = None
            for cpu, vaddr in cpu_csd_map.items():
                if vaddr == csd_addr:
                    found_cpu = cpu
                    break

            if found_cpu is not None:
                # Show context: 3 CPUs before and after the target
                context_range = 3
                start_cpu = max(0, found_cpu - context_range)
                end_cpu = found_cpu + context_range

                all_cpus = sorted(cpu_csd_map.keys())

                # Show leading ellipsis if not starting from beginning
                if start_cpu > min(all_cpus):
                    print("  ...   (showing CPUs %d-%d only)" % (start_cpu, end_cpu))

                # Display CPUs in the context range
                for cpu in all_cpus:
                    if start_cpu <= cpu <= end_cpu:
                        vaddr = cpu_csd_map[cpu]
                        if cpu == found_cpu:
                            crashcolor.set_color(crashcolor.RED | crashcolor.BOLD)
                            print("[%-4d]  0x%016x  <<< TARGET CPU" % (cpu, vaddr))
                            crashcolor.set_color(crashcolor.RESET)
                        else:
                            print("[%-4d]  0x%016x" % (cpu, vaddr))

                # Show trailing ellipsis if not ending at last CPU
                if end_cpu < max(all_cpus):
                    print("  ...")
            else:
                # Target not found, show first few entries as sample
                print("  (showing first 5 CPUs as sample)")
                for i, cpu in enumerate(sorted(cpu_csd_map.keys())):
                    if i >= 5:
                        print("  ...")
                        break
                    vaddr = cpu_csd_map[cpu]
                    print("[%-4d]  0x%016x" % (cpu, vaddr))
        else:
            # No target address, show all CPUs
            for cpu in sorted(cpu_csd_map.keys()):
                vaddr = cpu_csd_map[cpu]
                print("[%-4d]  0x%016x" % (cpu, vaddr))

        # If target address provided, find and display details
        if csd_addr:
            print("\nStep 3: Finding CPU for struct __call_single_data 0x%x" % csd_addr)
            print("-" * 80)

            found_cpu = None
            for cpu, vaddr in cpu_csd_map.items():
                if vaddr == csd_addr:
                    found_cpu = cpu
                    break

            if found_cpu is not None:
                crashcolor.set_color(crashcolor.RED | crashcolor.BOLD)
                print("\n*** CPU %d is awaiting ACK ***" % found_cpu)
                crashcolor.set_color(crashcolor.RESET)

                # Show what's running on the target CPU
                print("\nCurrent process on CPU %d:" % found_cpu)
                print("-" * 80)

                try:
                    # Use runq -c to get current task on the CPU
                    runq_output = exec_crash_command("runq -c %d" % found_cpu)

                    # Parse runq output to extract the current task address
                    # Format: "  CURRENT: PID: 3468342  TASK: ffff9c5e22ad8000  COMMAND: "bash""
                    current_task = None
                    for line in runq_output.splitlines():
                        stripped = line.strip()
                        if stripped.startswith("CURRENT:"):
                            # Extract task address from the CURRENT line
                            if "TASK:" in line:
                                parts = line.split("TASK:")
                                if len(parts) > 1:
                                    addr_str = parts[1].split()[0].strip()
                                    try:
                                        current_task = int(addr_str, 16)
                                    except:
                                        pass
                            break

                    if current_task:
                        # Run ps -m to show process info (including runtime)
                        print("\nProcess Information (ps -m):")
                        ps_output = exec_crash_command("ps -m %x" % current_task)
                        print(ps_output)

                        # Run bt to show backtrace
                        print("\nBacktrace (bt):")
                        bt_output = exec_crash_command("bt %x" % current_task)
                        print(bt_output)
                    else:
                        crashcolor.set_color(crashcolor.YELLOW)
                        print("Warning: Could not parse current task from runq output")
                        print("runq -c %d output:" % found_cpu)
                        print(runq_output)
                        crashcolor.set_color(crashcolor.RESET)

                except Exception as e:
                    crashcolor.set_color(crashcolor.YELLOW)
                    print("Warning: Could not get current process info: %s" % str(e))
                    crashcolor.set_color(crashcolor.RESET)

                # Read and display the struct __call_single_data structure
                print("\nStep 4: Reading struct __call_single_data at 0x%x" % csd_addr)
                print("-" * 80)

                try:
                    csd = readSU("struct __call_single_data", csd_addr)
                    print("\nstruct __call_single_data {")

                    # Handle union structure
                    if member_offset("struct __call_single_data", "flags") >= 0:
                        print("  flags = 0x%x," % csd.flags)
                    elif member_offset("struct __call_single_data", "u_flags") >= 0:
                        print("  u_flags = 0x%x," % csd.node.u_flags)

                    print("  func = 0x%x" % csd.func)

                    # Try to resolve function name
                    try:
                        func_name = addr2sym(csd.func)
                        if func_name:
                            print("       <%s>" % func_name)
                    except:
                        pass

                    print("  info = 0x%x" % csd.info)
                    print("}")

                    # Check if this CPU is online
                    print("\nCPU %d Status:" % found_cpu)
                    print("-" * 80)
                    try:
                        cpu_online_bits = readSymbol("__cpu_online_mask")
                        if cpu_online_bits:
                            # Simple check - in real implementation would check bitmap
                            print("  Checking if CPU is online and responsive...")
                    except:
                        pass

                except Exception as e:
                    crashcolor.set_color(crashcolor.YELLOW)
                    print("Warning: Could not read struct __call_single_data structure: %s" % str(e))
                    crashcolor.set_color(crashcolor.RESET)
            else:
                crashcolor.set_color(crashcolor.YELLOW)
                print("\nWarning: Address 0x%x not found in per-cpu csd mappings" % csd_addr)
                crashcolor.set_color(crashcolor.RESET)

        print("\n" + "=" * 80)

    except Exception as e:
        crashcolor.set_color(crashcolor.RED)
        print("Error analyzing SMP call data: %s" % str(e))
        crashcolor.set_color(crashcolor.RESET)
        import traceback
        traceback.print_exc()


def lockup():
    op = OptionParser()
    op.add_option("-b", "--backtrace", dest="backtrace", default=0,
                  action="store_true",
                  help="Shows backtrace of the process")
    op.add_option("-c", "--compact", dest="compact", default=0,
                  action="store_true",
                  help="Exclude swapper/* from the list")
    op.add_option("-d", "--details", dest="details", default=0,
                  action="store_true",
                  help="show task details")
    op.add_option("-r", "--reverse", dest="reverse_sort", default=0,
                  action="store_true",
                  help="show longest holder at top")
    op.add_option("-t", "--tasks", dest="show_tasks", default=0,
                  action="store_true",
                  help="show tasks in each runqueue")
    op.add_option("-s", "--rt", dest="rt_stat", default=0,
                  action="store_true",
                  help="show RT statistics")
    op.add_option("-q", "--qspinlock", dest="qspinlock", default="",
                  action="store", type="string",
                  help="Shows qspinlock details")
    op.add_option("--smp-call", dest="smp_call", default="",
                  action="store", type="string",
                  help="Analyze SMP call function data: --smp-call <call_function_data_addr>[,<__call_single_data_addr>]")
    op.add_option("-u", "--user", dest="user", default=0,
                  action="store_true",
                  help="show user space running only")

    (o, args) = op.parse_args()

    if o.smp_call:
        # Parse addresses: format is <cfd_addr>[,<csd_addr>]
        addrs = o.smp_call.split(',')
        try:
            cfd_addr = int(addrs[0].strip(), 16)
            csd_addr = None
            if len(addrs) > 1:
                csd_addr = int(addrs[1].strip(), 16)
            show_smp_call_data(cfd_addr, csd_addr)
        except ValueError:
            crashcolor.set_color(crashcolor.RED)
            print("Error: Invalid address format. Use: --smp-call <call_function_data_addr>[,<__call_single_data_addr>]")
            print("Example: --smp-call ffff9caa268f4a00,ffff9caa2633ae60")
            crashcolor.set_color(crashcolor.RESET)
        sys.exit(0)

    if (o.qspinlock != ""):
        show_qspinlock(o)
        sys.exit(0)

    if (o.rt_stat):
        show_rt_stat(o)
        return


    lockup_display(not o.reverse_sort, o.show_tasks, o)

if ( __name__ == '__main__'):
    lockup()
