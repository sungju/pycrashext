"""
'rcuinfo' command: RCU (Read-Copy-Update) state, stall detection, and analysis.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *
from LinuxDump import percpu

import sys
import re
from optparse import OptionParser

import crashcolor


RCU_SEQ_STATE_MASK = 0x3

RCU_GP_STATE_NAMES = {
    0: "RCU_GP_IDLE",
    1: "RCU_GP_WAIT_HEAD",
    2: "RCU_GP_WAIT_FQS",
    3: "RCU_GP_DOING_FQS",
    4: "RCU_GP_CLEANUP",
    5: "RCU_GP_CLEANED",
}


def get_rcu_states():
    states = []
    try:
        rs = readSymbol("rcu_state")
        if isinstance(rs, list):
            states = list(rs)
        else:
            states = [rs]
    except:
        pass

    if not states:
        for name in ["rcu_sched_state", "rcu_preempt_state", "rcu_bh_state"]:
            try:
                rs = readSymbol(name)
                if rs:
                    states.append(rs)
            except:
                pass

    return states


def get_rcu_state_name(rs):
    try:
        return rs.name
    except:
        pass
    try:
        sym = addr2sym(int(rs))
        if sym:
            return sym
    except:
        pass
    return "rcu_state@0x%x" % int(rs)


def gp_seq_to_num(gp_seq):
    return gp_seq >> 2


def gp_seq_to_state(gp_seq):
    return gp_seq & RCU_SEQ_STATE_MASK


def get_gp_state_name(state_val):
    return RCU_GP_STATE_NAMES.get(state_val, "UNKNOWN(%d)" % state_val)


def get_rcu_stall_lines():
    stall_patterns = [
        "rcu_sched self-detected stall",
        "rcu_preempt self-detected stall",
        "rcu_bh self-detected stall",
        "RCU self-detected stall",
        "rcu_sched kthread starved",
        "rcu_preempt kthread starved",
        "All QSes seen",
        "rcu_sched detected stalls",
        "rcu_preempt detected stalls",
        "INFO: rcu_sched",
        "INFO: rcu_preempt",
    ]
    try:
        log_output = exec_crash_command("log")
    except:
        return []

    stall_lines = []
    for line in log_output.splitlines():
        for pat in stall_patterns:
            if pat in line:
                stall_lines.append(line.strip())
                break

    return stall_lines


def show_rcu_summary(options):
    crashcolor.set_color(crashcolor.BLUE)
    print("=" * 60)
    print(" RCU State Summary")
    print("=" * 60)
    crashcolor.set_color(crashcolor.RESET)

    states = get_rcu_states()
    if not states:
        crashcolor.set_color(crashcolor.RED)
        print("  Could not read rcu_state symbol")
        crashcolor.set_color(crashcolor.RESET)
        return

    for rs in states:
        name = get_rcu_state_name(rs)
        crashcolor.set_color(crashcolor.CYAN)
        print("\n  RCU flavor : %s (0x%x)" % (name, int(rs)))
        crashcolor.set_color(crashcolor.RESET)

        try:
            gp_seq = rs.gp_seq
            print("  gp_seq     : %d  (GP #%d, phase %d)" %
                  (gp_seq, gp_seq_to_num(gp_seq), gp_seq_to_state(gp_seq)))
        except:
            try:
                gpnum = rs.gpnum
                completed = rs.completed
                print("  gpnum      : %d" % gpnum)
                print("  completed  : %d" % completed)
                if gpnum != completed:
                    crashcolor.set_color(crashcolor.YELLOW)
                    print("  ** Grace period %d in progress **" % gpnum)
                    crashcolor.set_color(crashcolor.RESET)
            except:
                print("  (could not read grace period info)")

        try:
            gp_state = rs.gp_state
            print("  gp_state   : %s" % get_gp_state_name(gp_state))
        except:
            pass

        try:
            n_force_qs = rs.n_force_qs
            n_force_qs_lh = rs.n_force_qs_lh
            print("  force_qs   : %d (last-half: %d)" % (n_force_qs, n_force_qs_lh))
        except:
            pass

        try:
            num_nodes = rs.rcu_num_nodes
            print("  rcu_nodes  : %d" % num_nodes)
        except:
            pass

        try:
            num_levels = rs.num_lvls
            print("  tree_levels: %d" % num_levels)
        except:
            pass

    stall_lines = get_rcu_stall_lines()
    if stall_lines:
        crashcolor.set_color(crashcolor.RED | crashcolor.BOLD)
        print("\n  *** %d RCU stall warning(s) found in dmesg ***" % len(stall_lines))
        crashcolor.set_color(crashcolor.RESET)
        print("  Use 'rcuinfo -s' for details.")
    else:
        crashcolor.set_color(crashcolor.GREEN)
        print("\n  No RCU stall warnings found in dmesg.")
        crashcolor.set_color(crashcolor.RESET)


def show_stall_analysis(options):
    crashcolor.set_color(crashcolor.BLUE)
    print("=" * 60)
    print(" RCU Stall Analysis")
    print("=" * 60)
    crashcolor.set_color(crashcolor.RESET)

    stall_lines = get_rcu_stall_lines()
    if not stall_lines:
        crashcolor.set_color(crashcolor.GREEN)
        print("\n  No RCU stall warnings found in dmesg.")
        crashcolor.set_color(crashcolor.RESET)
        return

    crashcolor.set_color(crashcolor.RED)
    print("\n  Found %d RCU stall warning(s):\n" % len(stall_lines))
    crashcolor.set_color(crashcolor.RESET)

    for i, line in enumerate(stall_lines):
        crashcolor.set_color(crashcolor.YELLOW)
        print("  [%d] " % (i + 1), end="")
        crashcolor.set_color(crashcolor.RESET)
        print(line)

    # Extract CPU numbers from stall messages
    stalled_cpus = set()
    for line in stall_lines:
        cpu_matches = re.findall(r'\bcpu[=: ]*(\d+)', line, re.IGNORECASE)
        stalled_cpus.update(int(c) for c in cpu_matches)
        cpu_matches = re.findall(r'\b(\d+)-\.\.\.\.:', line)
        stalled_cpus.update(int(c) for c in cpu_matches)
        cpu_matches = re.findall(r'\((\d+) ticks', line)
        stalled_cpus.update(int(c) for c in cpu_matches)

    # Also look for the detailed stall CPU list pattern: "N-....: ..."
    try:
        log_output = exec_crash_command("log")
        for line in log_output.splitlines():
            if "self-detected stall" in line or "detected stalls" in line:
                continue
            m = re.match(r'.*\s+(\d+)-\.\.\.\.:', line)
            if m:
                stalled_cpus.add(int(m.group(1)))
    except:
        pass

    if stalled_cpus:
        crashcolor.set_color(crashcolor.CYAN)
        print("\n  CPUs mentioned in stall warnings: %s" %
              ", ".join(str(c) for c in sorted(stalled_cpus)))
        crashcolor.set_color(crashcolor.RESET)

    # Show context around stalls from full log
    print("\n  --- Full RCU stall context from dmesg ---\n")
    try:
        log_output = exec_crash_command("log")
        log_lines = log_output.splitlines()
        printed_ranges = set()

        for idx, line in enumerate(log_lines):
            is_rcu_line = False
            for pat in ["self-detected stall", "detected stalls",
                        "rcu_sched kthread starved", "rcu_preempt kthread starved",
                        "INFO: rcu_"]:
                if pat in line:
                    is_rcu_line = True
                    break

            if is_rcu_line:
                start = max(0, idx - 2)
                end = min(len(log_lines), idx + 15)
                range_key = (start, end)
                if range_key in printed_ranges:
                    continue
                printed_ranges.add(range_key)

                crashcolor.set_color(crashcolor.YELLOW)
                print("  --- stall block (lines %d-%d) ---" % (start + 1, end))
                crashcolor.set_color(crashcolor.RESET)
                for j in range(start, end):
                    if j == idx:
                        crashcolor.set_color(crashcolor.RED)
                    print("  %s" % log_lines[j])
                    if j == idx:
                        crashcolor.set_color(crashcolor.RESET)
                print()
    except:
        print("  (could not read full log)")


def show_grace_period(options):
    crashcolor.set_color(crashcolor.BLUE)
    print("=" * 60)
    print(" RCU Grace Period Details")
    print("=" * 60)
    crashcolor.set_color(crashcolor.RESET)

    states = get_rcu_states()
    if not states:
        print("  Could not read rcu_state")
        return

    try:
        jiffies_val = readSymbol("jiffies")
    except:
        jiffies_val = None

    for rs in states:
        name = get_rcu_state_name(rs)
        crashcolor.set_color(crashcolor.CYAN)
        print("\n  [%s]" % name)
        crashcolor.set_color(crashcolor.RESET)

        # Grace period sequence (newer kernels)
        try:
            gp_seq = rs.gp_seq
            gp_num = gp_seq_to_num(gp_seq)
            gp_phase = gp_seq_to_state(gp_seq)
            print("  gp_seq          : %d (GP #%d, phase %d)" %
                  (gp_seq, gp_num, gp_phase))

            phase_names = {0: "idle", 1: "started", 2: "wait", 3: "done"}
            print("  gp_phase_meaning: %s" % phase_names.get(gp_phase, "unknown"))
        except:
            try:
                gpnum = rs.gpnum
                completed = rs.completed
                print("  gpnum           : %d" % gpnum)
                print("  completed       : %d" % completed)
                pending = gpnum - completed
                if pending > 0:
                    crashcolor.set_color(crashcolor.YELLOW)
                    print("  pending_gps     : %d" % pending)
                    crashcolor.set_color(crashcolor.RESET)
            except:
                print("  (could not read GP numbers)")

        # GP state
        try:
            gp_state = rs.gp_state
            print("  gp_state        : %d (%s)" %
                  (gp_state, get_gp_state_name(gp_state)))
        except:
            pass

        # GP start time
        try:
            gp_start = rs.gp_start
            print("  gp_start        : %d (jiffies)" % gp_start)
            if jiffies_val is not None:
                delta = jiffies_val - gp_start
                if delta > 0:
                    hz = try_get_hz()
                    if hz > 0:
                        secs = delta / hz
                        print("  gp_age          : %d jiffies (%.2f seconds)" %
                              (delta, secs))
                    else:
                        print("  gp_age          : %d jiffies" % delta)
        except:
            pass

        # Expedited grace periods
        try:
            exp_seq = rs.expedited_sequence
            print("  expedited_seq   : %d (GP #%d)" %
                  (exp_seq, gp_seq_to_num(exp_seq)))
        except:
            pass

        # Stall jiffies threshold
        try:
            jiffies_stall = rs.jiffies_stall
            print("  jiffies_stall   : %d" % jiffies_stall)
            if jiffies_val is not None:
                delta = jiffies_stall - jiffies_val
                hz = try_get_hz()
                if hz > 0:
                    print("  stall_in        : %d jiffies (%.2f seconds %s)" %
                          (abs(delta), abs(delta) / hz,
                           "ago" if delta < 0 else "from now"))
        except:
            pass

        # Force quiescent state counters
        try:
            print("  n_force_qs      : %d" % rs.n_force_qs)
        except:
            pass
        try:
            print("  n_force_qs_lh   : %d" % rs.n_force_qs_lh)
        except:
            pass
        try:
            print("  n_force_qs_ngp  : %d" % rs.n_force_qs_ngp)
        except:
            pass


def try_get_hz():
    try:
        return readSymbol("tick_nsec")
        # Actually, HZ is not directly a symbol. Let's compute from jiffies info.
    except:
        pass
    try:
        result = exec_crash_command("help -k")
        for line in result.splitlines():
            if "HZ:" in line or "hz:" in line.lower():
                parts = line.split(":")
                return int(parts[-1].strip())
    except:
        pass
    try:
        result = exec_crash_command("sys")
        for line in result.splitlines():
            if "HZ:" in line:
                parts = line.split()
                for p in parts:
                    try:
                        return int(p)
                    except:
                        continue
    except:
        pass
    return 0


def show_node_tree(options):
    crashcolor.set_color(crashcolor.BLUE)
    print("=" * 60)
    print(" RCU Node Tree")
    print("=" * 60)
    crashcolor.set_color(crashcolor.RESET)

    states = get_rcu_states()
    if not states:
        print("  Could not read rcu_state")
        return

    for rs in states:
        name = get_rcu_state_name(rs)
        crashcolor.set_color(crashcolor.CYAN)
        print("\n  [%s]" % name)
        crashcolor.set_color(crashcolor.RESET)

        try:
            num_nodes = rs.rcu_num_nodes
        except:
            num_nodes = 0

        try:
            num_levels = rs.num_lvls
        except:
            num_levels = 0

        if num_nodes == 0 and num_levels == 0:
            print("  (could not determine tree size)")
            continue

        print("  Nodes: %d, Levels: %d" % (num_nodes, num_levels))

        # Get level span info
        level_info = []
        try:
            for lvl in range(num_levels):
                try:
                    levelcnt = rs.levelcnt[lvl]
                    levelspread = rs.levelspread[lvl]
                    level_info.append((levelcnt, levelspread))
                except:
                    break
        except:
            pass

        if level_info:
            for lvl, (cnt, spread) in enumerate(level_info):
                print("    Level %d: %d node(s), spread %d" % (lvl, cnt, spread))

        # Traverse node array
        node_idx = 0
        try:
            nodes = rs.node
            current_level = 0
            level_start = 0

            for i in range(num_nodes):
                node = nodes[i]

                # Determine level from grplo/grphi or by counting
                try:
                    grplo = node.grplo
                    grphi = node.grphi
                    level = node.level
                except:
                    grplo = 0
                    grphi = 0
                    level = 0

                # Get quiescent state masks
                try:
                    qsmask = node.qsmask
                    qsmaskinit = node.qsmaskinit
                except:
                    qsmask = 0
                    qsmaskinit = 0

                indent = "    " + "  " * level
                has_pending = qsmask != 0

                if has_pending:
                    crashcolor.set_color(crashcolor.RED)
                print("%snode[%d] (0x%x) level=%d CPUs=%d-%d "
                      "qsmask=0x%lx qsmaskinit=0x%lx" %
                      (indent, i, int(node), level, grplo, grphi,
                       qsmask, qsmaskinit))
                if has_pending:
                    crashcolor.set_color(crashcolor.RESET)

                # Show GP sequence for this node
                try:
                    node_gp_seq = node.gp_seq
                    print("%s  gp_seq=%d" % (indent, node_gp_seq))
                except:
                    pass

                # Show blocked tasks count
                try:
                    blkd_count = count_list_entries(node.blkd_tasks)
                    if blkd_count > 0:
                        crashcolor.set_color(crashcolor.YELLOW)
                        print("%s  blocked_tasks: %d" % (indent, blkd_count))
                        crashcolor.set_color(crashcolor.RESET)
                except:
                    pass

                # Show boost info if available
                try:
                    if node.exp_need_qs:
                        print("%s  exp_need_qs: %d" % (indent, node.exp_need_qs))
                except:
                    pass

        except Exception as e:
            print("  Error traversing node tree: %s" % str(e))


def count_list_entries(list_head):
    count = 0
    try:
        head_addr = int(list_head)
        if head_addr == 0:
            return 0
        next_addr = int(list_head.next)
        if next_addr == 0 or next_addr == head_addr:
            return 0
        current = next_addr
        while current != head_addr and count < 10000:
            count += 1
            entry = readSU("struct list_head", current)
            current = int(entry.next)
    except:
        pass
    return count


def show_callbacks(options):
    crashcolor.set_color(crashcolor.BLUE)
    print("=" * 60)
    print(" RCU Per-CPU Callback Info")
    print("=" * 60)
    crashcolor.set_color(crashcolor.RESET)

    cpu_data_list = []

    # Try per-CPU rcu_data variable
    try:
        addrs = percpu.get_cpu_var("rcu_data")
        for cpu, addr in enumerate(addrs):
            rd = readSU("struct rcu_data", addr)
            cpu_data_list.append((cpu, rd))
    except:
        pass

    # Fallback: try rcu_state.rda per-CPU pointer
    if not cpu_data_list:
        try:
            states = get_rcu_states()
            for rs in states:
                try:
                    rda_addrs = percpu.get_cpu_var_from_addr(int(rs.rda))
                    for cpu, addr in enumerate(rda_addrs):
                        rd = readSU("struct rcu_data", readULong(addr))
                        cpu_data_list.append((cpu, rd))
                    break
                except:
                    continue
        except:
            pass

    if not cpu_data_list:
        print("\n  Could not read per-CPU rcu_data")
        return

    total_cbs = 0
    cpu_cb_counts = []

    print("\n  %5s  %12s  %12s  %10s  %s" %
          ("CPU", "gp_seq", "callbacks", "passed_qs", "state"))
    print("  %s" % ("-" * 60))

    for cpu, rd in cpu_data_list:
        # Get callback count
        cb_count = 0
        try:
            cb_count = rd.cblist.len
        except:
            try:
                cb_count = rd.qlen
            except:
                pass

        # Get GP sequence for this CPU
        cpu_gp_seq = 0
        try:
            cpu_gp_seq = rd.gp_seq
        except:
            try:
                cpu_gp_seq = rd.completed
            except:
                pass

        # Get passed_quiesce state
        passed_qs = ""
        try:
            if rd.cpu_no_qs.b.norm:
                passed_qs = "need_qs"
            else:
                passed_qs = "passed"
        except:
            try:
                if rd.passed_quiesce:
                    passed_qs = "passed"
                else:
                    passed_qs = "need_qs"
            except:
                passed_qs = "?"

        # Determine state
        state = ""
        try:
            if rd.rcu_urgent_qs:
                state = "URGENT"
            elif rd.rcu_need_heavy_qs:
                state = "HEAVY"
        except:
            pass

        if cb_count > 0:
            crashcolor.set_color(crashcolor.YELLOW)

        print("  %5d  %12d  %12d  %10s  %s" %
              (cpu, cpu_gp_seq, cb_count, passed_qs, state))

        if cb_count > 0:
            crashcolor.set_color(crashcolor.RESET)

        total_cbs += cb_count
        cpu_cb_counts.append((cpu, cb_count))

    # Summary
    print()
    crashcolor.set_color(crashcolor.CYAN)
    print("  Total pending callbacks: %d" % total_cbs)
    crashcolor.set_color(crashcolor.RESET)

    if total_cbs > 0:
        cpu_cb_counts.sort(key=lambda x: x[1], reverse=True)
        top = cpu_cb_counts[:5]
        if top[0][1] > 0:
            print("  Top CPUs by callback count:")
            for cpu, count in top:
                if count > 0:
                    print("    CPU %d: %d" % (cpu, count))


def show_blocked_tasks(options):
    crashcolor.set_color(crashcolor.BLUE)
    print("=" * 60)
    print(" Tasks Blocked in RCU Critical Sections")
    print("=" * 60)
    crashcolor.set_color(crashcolor.RESET)

    states = get_rcu_states()
    if not states:
        print("  Could not read rcu_state")
        return

    total_blocked = 0

    for rs in states:
        name = get_rcu_state_name(rs)

        try:
            num_nodes = rs.rcu_num_nodes
        except:
            num_nodes = 0

        if num_nodes == 0:
            continue

        try:
            nodes = rs.node
        except:
            continue

        for i in range(num_nodes):
            try:
                node = nodes[i]
            except:
                break

            # Walk blkd_tasks list
            try:
                blkd_head = node.blkd_tasks
                head_addr = int(blkd_head)
                if head_addr == 0:
                    continue
                next_addr = int(blkd_head.next)
                if next_addr == 0 or next_addr == head_addr:
                    continue
            except:
                continue

            # Found blocked tasks in this node
            current = next_addr
            node_blocked = 0
            while current != head_addr and node_blocked < 10000:
                try:
                    # task_struct.rcu_node_entry is the list entry
                    entry_offset = member_offset("struct task_struct",
                                                 "rcu_node_entry")
                    task_addr = current - entry_offset
                    task = readSU("struct task_struct", task_addr)

                    if total_blocked == 0 and node_blocked == 0:
                        crashcolor.set_color(crashcolor.CYAN)
                        print("\n  [%s]" % name)
                        crashcolor.set_color(crashcolor.RESET)

                    if node_blocked == 0:
                        print("\n  node[%d] (CPUs %d-%d):" %
                              (i, node.grplo, node.grphi))

                    pid = task.pid
                    comm = task.comm
                    state = task.state if hasattr(task, 'state') else 0
                    try:
                        state = task.__state
                    except:
                        try:
                            state = task.state
                        except:
                            state = 0

                    crashcolor.set_color(crashcolor.YELLOW)
                    print("    PID: %-8d  COMM: %-16s  STATE: 0x%x" %
                          (pid, comm, state))
                    crashcolor.set_color(crashcolor.RESET)

                    if options.verbose:
                        try:
                            bt = exec_crash_command("bt %d" % pid)
                            for line in bt.splitlines():
                                print("      %s" % line)
                            print()
                        except:
                            print("      (could not get backtrace)")

                    node_blocked += 1
                    total_blocked += 1

                    entry = readSU("struct list_head", current)
                    current = int(entry.next)
                except:
                    break

    if total_blocked == 0:
        crashcolor.set_color(crashcolor.GREEN)
        print("\n  No tasks blocked in RCU critical sections.")
        print("  (CONFIG_PREEMPT_RCU may not be enabled, or no tasks are blocked)")
        crashcolor.set_color(crashcolor.RESET)
    else:
        print("\n  Total blocked tasks: %d" % total_blocked)

    # Also check for tasks with RCU-related wait channels
    print()
    crashcolor.set_color(crashcolor.CYAN)
    print("  Tasks with RCU-related wait channels:")
    crashcolor.set_color(crashcolor.RESET)

    try:
        ps_output = exec_crash_command("ps -m")
        rcu_tasks = []
        for line in ps_output.splitlines():
            if "rcu" in line.lower():
                rcu_tasks.append(line.strip())

        if rcu_tasks:
            for line in rcu_tasks:
                print("    %s" % line)
        else:
            print("    (none found)")
    except:
        print("    (could not check)")

    # Show RCU kthreads
    print()
    crashcolor.set_color(crashcolor.CYAN)
    print("  RCU kernel threads:")
    crashcolor.set_color(crashcolor.RESET)

    try:
        ps_output = exec_crash_command("ps")
        for line in ps_output.splitlines():
            if line.startswith("  ") or line.startswith(">"):
                fields = line.split()
                if len(fields) >= 6:
                    comm = fields[-1]
                    if comm.startswith("rcu_") or comm.startswith("rcuo") or \
                       comm == "rcu_gp" or comm == "rcu_par_gp" or \
                       comm.startswith("rcu_tasks") or \
                       comm.startswith("rcuog") or comm.startswith("rcuop") or \
                       comm.startswith("rcuos"):
                        print("    %s" % line.strip())
    except:
        print("    (could not list)")


def rcuinfo():
    op = OptionParser()
    op.add_option("-s", "--stall", dest="stall", default=0,
                  action="store_true",
                  help="Show detailed RCU stall analysis from dmesg")
    op.add_option("-g", "--gp", dest="gp", default=0,
                  action="store_true",
                  help="Show grace period details")
    op.add_option("-n", "--node", dest="node", default=0,
                  action="store_true",
                  help="Show RCU node tree with quiescent state masks")
    op.add_option("-c", "--callbacks", dest="callbacks", default=0,
                  action="store_true",
                  help="Show per-CPU RCU callback info")
    op.add_option("-t", "--tasks", dest="tasks", default=0,
                  action="store_true",
                  help="Show tasks blocked in RCU critical sections")
    op.add_option("-a", "--all", dest="show_all", default=0,
                  action="store_true",
                  help="Show all RCU information")
    op.add_option("-v", "--verbose", dest="verbose", default=0,
                  action="store_true",
                  help="Show additional details (backtraces for blocked tasks)")

    (o, args) = op.parse_args()

    if o.show_all:
        show_rcu_summary(o)
        print()
        show_grace_period(o)
        print()
        show_node_tree(o)
        print()
        show_callbacks(o)
        print()
        show_blocked_tasks(o)
        sys.exit(0)

    if o.stall:
        show_stall_analysis(o)
        sys.exit(0)

    if o.gp:
        show_grace_period(o)
        sys.exit(0)

    if o.node:
        show_node_tree(o)
        sys.exit(0)

    if o.callbacks:
        show_callbacks(o)
        sys.exit(0)

    if o.tasks:
        show_blocked_tasks(o)
        sys.exit(0)

    # Default: summary
    show_rcu_summary(o)


if ( __name__ == '__main__'):
    rcuinfo()
