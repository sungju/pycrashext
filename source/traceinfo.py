"""
 Written by Daniel Sungju Kwon
"""
from pykdump.API import *

from LinuxDump import Tasks
from LinuxDump.trees import *

import sys
import crashcolor


def get_module_name(symbol):
    result = exec_crash_command("sym %s" % symbol)
    if result == None or result == "":
        return ""
    name = result.split()[-1]
    if name.endswith("]"):
        return name
    return ""


def get_called_functions(handler_name):
    """Return unique function names called by handler_name via disassembly."""
    called = []
    seen = set()
    try:
        dis_out = exec_crash_command("dis %s" % handler_name)
        for line in dis_out.splitlines():
            stripped = line.strip()
            # Match direct call instructions on x86 and arm64
            is_call = any(op in stripped for op in
                          ('callq ', 'call ', '\tbl\t', ' bl ', '\tblr\t', ' blr '))
            if not is_call:
                continue
            # Extract symbol from <symbol+offset> or <symbol>
            if '<' in line and '>' in line:
                lt = line.rfind('<') + 1
                gt = line.rfind('>')
                if lt < gt:
                    sym = line[lt:gt].split('+')[0].strip()
                    if sym and not sym.startswith('0x') and sym not in seen:
                        seen.add(sym)
                        called.append(sym)
    except Exception:
        pass
    return called


def print_handler(tab_str, handler_type, handler_addr, kp, show_details=False):
    if handler_addr != 0:
        handler_name = addr2sym(handler_addr)
        mod_name = get_module_name(handler_name)
        rp_offset = member_offset("struct trace_kprobe", "rp")
        kp_offset = member_offset("struct kretprobe", "kp")
        if rp_offset >= 0 and kp_offset >= 0:
            trace_kprobe = readSU("struct trace_kprobe", kp - rp_offset - kp_offset)
            try:
                call_name = trace_kprobe.tp.call.name
            except:
                call_name = ""
        else:
            trace_kprobe = 0
            call_name = ""

        print("\t%s%s_handler = 0x%x (%s)%s : struct trace_kprobe 0x%x (%s)" % (tab_str, handler_type, handler_addr, handler_name,
                                                mod_name, trace_kprobe, call_name))
        if handler_name is not None and handler_name.endswith("_kretprobe"):
            kretprobe = readSU("struct kretprobe", kp)
            ret_handler_name = addr2sym(kretprobe.handler)
            mod_name = get_module_name(ret_handler_name)
            if mod_name != "":
                crashcolor.set_color(crashcolor.LIGHTRED)
            print("\t\t%skretprobe.handler = 0x%x (%s)%s" % (tab_str, kretprobe.handler,
                                                             ret_handler_name, mod_name))
            crashcolor.set_color(crashcolor.RESET)
        else:
            try:
                jprobe = readSU("struct jprobe", kp)
                if jprobe.entry != 0:
                    entry_handler_name = addr2sym(jprobe.entry)
                    mod_name = get_module_name(entry_handler_name)
                    if mod_name != "":
                        crashcolor.set_color(crashcolor.LIGHTRED)
                    if entry_handler_name != None:
                        print("\t\t%sjprobe.entry = 0x%x (%s)%s" % (tab_str, jprobe.entry,
                                                              entry_handler_name, mod_name))
                    crashcolor.set_color(crashcolor.RESET)
            except:
                pass

        # Show functions called by this handler (only with -d)
        if show_details and handler_name:
            called = get_called_functions(handler_name)
            if called:
                crashcolor.set_color(crashcolor.CYAN)
                print("\t\t%sCalled functions:" % tab_str)
                crashcolor.set_color(crashcolor.RESET)
                for func in called:
                    mod = get_module_name(func)
                    crashcolor.set_color(crashcolor.LIGHTCYAN)
                    print("\t\t\t%s-> %s%s" % (tab_str, func, mod))
                    crashcolor.set_color(crashcolor.RESET)




def print_handler_handler(handler_type, kprobe, show_details=False):
    for kp in readSUListFromHead(kprobe.list,
                                "list",
                                "struct kprobe"):
        if handler_type == "pre":
            print_handler("\t", handler_type, kp.pre_handler, kp, show_details)
        elif handler_type == "post":
            print_handler("\t", handler_type, kp.post_handler, kp, show_details)
        elif handler_type == "fault":
            print_handler("\t", handler_type, kp.fault_handler, kp, show_details)
        elif handler_type == "break":
            try:
                print_handler("\t", handler_type, kp.break_handler, kp, show_details)
            except:
                pass
        else:
            print("WHAT????")


def kprobe_flags_str(flags):
    result_str = ""

    if (flags & 1) == 1:
        result_str = result_str + "TP_FLAG_TRACE "

    if (flags & 2) == 2:
        result_str = result_str + "TP_FLAG_PROFILE "

    if (flags & 4) == 4:
        result_str = result_str + "TP_FLAG_REGISTERED "

    return result_str


# struct kprobe.flags bitmask (include/linux/kprobes.h)
_KPROBE_FLAGS = [
    (1,  "GONE"),           # breakpoint already removed from table
    (2,  "DISABLED"),       # probe temporarily disabled
    (4,  "OPTIMIZED"),      # using optimised (jump) patching
    (8,  "FTRACE"),         # using ftrace for patching
    (16, "ON_FUNC_ENTRY"),  # probe sits on function entry point
    (32, "AGGREGATED"),     # aggregate probe (multi-handler) [newer kernels]
]

def kprobe_flag_str(flags):
    """Return a human-readable string for struct kprobe.flags."""
    if flags == 0:
        return "0 (active)"
    parts = ["KPROBE_FLAG_%s" % name
             for bit, name in _KPROBE_FLAGS if flags & bit]
    unknown = flags & ~sum(bit for bit, _ in _KPROBE_FLAGS)
    if unknown:
        parts.append("UNKNOWN(0x%x)" % unknown)
    return " | ".join(parts) if parts else "0"


KPROBE_HASH_BITS = 6
GOLDEN_RATIO_64  = 0x61C8864680B583EB  # used by hash_long in 64-bit kernels


def hash_ptr_64(addr, bits):
    """Replicate Linux hash_ptr(addr, bits) for 64-bit systems."""
    h = (addr * GOLDEN_RATIO_64) & 0xFFFFFFFFFFFFFFFF
    return h >> (64 - bits)


def get_kprobe_by_ip(ip_addr):
    """
    Locate a kprobe by instruction-pointer address, mirroring get_kprobe():

        head = &kprobe_table[hash_ptr(addr, KPROBE_HASH_BITS)];
        hlist_for_each_entry_rcu(p, head, hlist)
            if (p->addr == addr) return p;
    """
    try:
        kprobe_table = readSymbol("kprobe_table")
        bucket = hash_ptr_64(ip_addr, KPROBE_HASH_BITS)
        head = kprobe_table[bucket]
        kprobe_iter = hlist_for_each_entry("struct kprobe", head, "hlist")
        while True:
            try:
                kp = next(kprobe_iter)
            except StopIteration:
                break
            except Exception:
                break
            try:
                if int(kp.addr) == ip_addr:
                    return kp
            except Exception:
                continue
    except Exception as e:
        print("Error in get_kprobe_by_ip: %s" % e)
    return None


def show_kprobe_by_ip(options, ip_addr):
    """Show the kprobe registered for a specific IP address."""
    sym = addr2sym(ip_addr)
    print("Looking up kprobe for ip = 0x%x (%s)" % (ip_addr, sym if sym else "?"))
    print("  bucket index = %d (KPROBE_HASH_BITS=%d)\n" %
          (hash_ptr_64(ip_addr, KPROBE_HASH_BITS), KPROBE_HASH_BITS))

    kp = get_kprobe_by_ip(ip_addr)
    if kp is None:
        print("No kprobe found for address 0x%x" % ip_addr)
        return

    tp_offset = member_offset("struct trace_probe", "rp")
    tp_offset = tp_offset + member_offset("struct kretprobe", "kp")

    print("struct kprobe 0x%x" % kp)
    try:
        print("\taddr = 0x%x (%s)" % (kp.addr, addr2sym(kp.addr)))
    except Exception:
        print("\taddr = (unreadable)")

    sd = options.show_details
    print_handler("", "pre",   kp.pre_handler,   kp, sd)
    print_handler_handler("pre",   kp, sd)
    print_handler("", "post",  kp.post_handler,  kp, sd)
    print_handler_handler("post",  kp, sd)
    print_handler("", "fault", kp.fault_handler, kp, sd)
    print_handler_handler("fault", kp, sd)
    try:
        print_handler("", "break", kp.break_handler, kp, sd)
    except Exception:
        pass
    print_handler_handler("break", kp, sd)

    if sd:
        try:
            print("\t\tkprobe.flags : %s" % kprobe_flag_str(int(kp.flags)))
        except Exception:
            pass
        try:
            trace_probe = readSU("struct trace_probe", kp - tp_offset)
            print("\t\tflags : %s" % kprobe_flags_str(trace_probe.flags))
            print("\t\tcall.name = '%s'" % trace_probe.call.name)
        except Exception:
            pass


def show_ftrace_list(options):
    kprobe_table_list = readSymbol("kprobe_table")
    tp_offset = member_offset("struct trace_probe", "rp")
    tp_offset = tp_offset + member_offset("struct kretprobe", "kp")
    for hh in kprobe_table_list:
        try:
            kprobe_iter = hlist_for_each_entry("struct kprobe", hh, "hlist")
        except Exception:
            continue
        while True:
            try:
                kprobe = next(kprobe_iter)
            except StopIteration:
                break
            except Exception as e:
                print("  (hlist walk error, skipping bucket: %s)" % e)
                break
            try:
                print("struct kprobe 0x%x" % (kprobe))
                try:
                    if kprobe.addr != 0:
                        print("\taddr = 0x%x (%s)" % (kprobe.addr, addr2sym(kprobe.addr)))
                except Exception:
                    print("\taddr = (unreadable)")
                sd = options.show_details
                print_handler("", "pre", kprobe.pre_handler, kprobe, sd)
                print_handler_handler("pre", kprobe, sd)
                print_handler("", "post", kprobe.post_handler, kprobe, sd)
                print_handler_handler("post", kprobe, sd)
                print_handler("", "fault", kprobe.fault_handler, kprobe, sd)
                print_handler_handler("fault", kprobe, sd)
                try:
                    print_handler("", "break", kprobe.break_handler, kprobe, sd)
                except Exception:
                    pass
                print_handler_handler("break", kprobe, sd)
                if options.show_details:
                    try:
                        print("\t\tkprobe.flags : %s" % kprobe_flag_str(int(kprobe.flags)))
                    except Exception:
                        pass
                    try:
                        trace_probe = readSU("struct trace_probe", kprobe - tp_offset)
                        print("\t\tflags : %s" % (kprobe_flags_str(trace_probe.flags)))
                        print("\t\tcall.name = '%s'" % (trace_probe.call.name))
                    except Exception:
                        pass
            except Exception as e:
                print("  (skipping kprobe: %s)" % e)
                continue


    if options.show_details:
        ftrace_events_list = readSymbol("ftrace_events")
        print("\nftrace_events")
        count = 0
        for ftrace_event_call in readSUListFromHead(ftrace_events_list,
                                                    "list",
                                                    "struct ftrace_event_call"):
            try:
                print("\t0x%x: name = %s" % (ftrace_event_call, ftrace_event_call.name))
                count = count + 1
            except:
                pass

        print("\n\ttotal event : %d" % (count))


    global_trace = readSymbol("global_trace")
    print("\n")
    if member_offset("struct trace_array", "trace_buffer") >= 0:
        trace_buffer = global_trace.trace_buffer
    elif member_offset("struct trace_array", "array_buffer") >= 0:
        trace_buffer = global_trace.array_buffer
    else:
        trace_buffer = None

    try:
        ftrace_enabled = (global_trace.buffer_disabled == 0 and
                          trace_buffer is not None and
                          trace_buffer.buffer.record_disabled.counter == 0)
    except (KeyError, AttributeError):
        # record_disabled field absent in some kernel versions — fall back to
        # buffer_disabled only
        try:
            ftrace_enabled = (global_trace.buffer_disabled == 0)
        except Exception:
            ftrace_enabled = True

    if ftrace_enabled:
        print("** ftrace Enabled (struct trace_array 0x%x)" % global_trace)
    else:
        print("** ftrace Disabled")

    current_trace = global_trace.current_trace
    print("current_tracer = '%s' (struct tracer 0x%x)" % (current_trace.name, current_trace))


def show_trace_types(options):
    trace_types = readSymbol("trace_types")
    for tracer in readStructNext(trace_types,
                                     "next",
                                 inchead = False):
        print(tracer)
        init_name = ""
        try:
            init_name = addr2sym(tracer.init)
        except:
            pass
        print("\tname = %s, init = 0x%x (%s)" %
              (tracer.name, tracer.init, init_name))


def show_trace_modules(options):
    tracepoint_module_list = readSymbol("tracepoint_module_list")
    for tp_module in readSUListFromHead(tracepoint_module_list,
                                        "list",
                                        "struct tp_module"):
        print(tp_module)
        tp_ptrs_name = ""
        try:
            tp_ptrs_name = addr2sym(tp_module.tracepoints_ptrs)
        except:
            pass
        print("\ttracepoints_ptrs = 0x%x (%s)" %
              (tp_module.tracepoints_ptrs, tp_ptrs_name))


BPF_PROG_TYPES = {
    0: "UNSPEC",           1: "SOCKET_FILTER",
    2: "KPROBE",           3: "SCHED_CLS",
    4: "SCHED_ACT",        5: "TRACEPOINT",
    6: "XDP",              7: "PERF_EVENT",
    8: "CGROUP_SKB",       9: "CGROUP_SOCK",
    10: "LWT_IN",          11: "LWT_OUT",
    12: "LWT_XMIT",        13: "SOCK_OPS",
    14: "SK_SKB",          15: "CGROUP_DEVICE",
    16: "SK_MSG",          17: "RAW_TRACEPOINT",
    18: "CGROUP_SOCK_ADDR", 19: "LWT_SEG6LOCAL",
    20: "LIRC_MODE2",      21: "SK_REUSEPORT",
    22: "FLOW_DISSECTOR",  23: "CGROUP_SYSCTL",
    24: "RAW_TP_WRITABLE", 25: "CGROUP_SOCKOPT",
    26: "TRACING",         27: "STRUCT_OPS",
    28: "EXT",             29: "LSM",
    30: "SK_LOOKUP",
}

BPF_MAP_TYPES = {
    0: "UNSPEC",              1: "HASH",
    2: "ARRAY",               3: "PROG_ARRAY",
    4: "PERF_EVENT_ARRAY",    5: "PERCPU_HASH",
    6: "PERCPU_ARRAY",        7: "STACK_TRACE",
    8: "CGROUP_ARRAY",        9: "LRU_HASH",
    10: "LRU_PERCPU_HASH",    11: "LPM_TRIE",
    12: "ARRAY_OF_MAPS",      13: "HASH_OF_MAPS",
    14: "DEVMAP",             15: "SOCKMAP",
    16: "CPUMAP",             17: "XSKMAP",
    18: "SOCKHASH",           19: "CGROUP_STORAGE",
    20: "REUSEPORT_SOCKARRAY", 21: "PERCPU_CGROUP_STORAGE",
    22: "QUEUE",              23: "STACK",
    24: "SK_STORAGE",         25: "DEVMAP_HASH",
    26: "STRUCT_OPS",         27: "RINGBUF",
    28: "INODE_STORAGE",      29: "TASK_STORAGE",
}

# Tracing-related types get YELLOW, network types get CYAN
_TRACING_TYPES = {2, 5, 7, 17, 24, 26, 29}
_NETWORK_TYPES = {1, 3, 4, 6, 13, 14, 16, 21, 22, 30}


def _bpf_prog_type_str(prog_type):
    return BPF_PROG_TYPES.get(prog_type, "UNKNOWN_%d" % prog_type)


def _bpf_map_type_str(map_type):
    return BPF_MAP_TYPES.get(map_type, "UNKNOWN_%d" % map_type)


def _bpf_prog_color(prog_type):
    if prog_type in _TRACING_TYPES:
        return crashcolor.YELLOW
    if prog_type in _NETWORK_TYPES:
        return crashcolor.CYAN
    return crashcolor.RESET


def _build_bpf_prog_to_process_map():
    """Build mapping of bpf_prog addresses to (PID, command) using crash files command"""
    prog_to_process = {}

    try:
        bpf_prog_fops_addr = sym2addr("bpf_prog_fops")
        init_task = readSymbol("init_task")

        for task in readSUListFromHead(init_task.tasks, "tasks", "struct task_struct", maxel=1000000):
            try:
                pid = task.pid
                comm = task.comm

                # Skip kernel threads (no mm)
                if not task.mm:
                    continue

                output = exec_crash_command("files %d" % pid)

                for line in output.splitlines():
                    if 'bpf-prog' not in line:
                        continue

                    parts = line.strip().split()
                    if len(parts) < 6:
                        continue

                    file_addr_str = parts[1]
                    file_addr = int(file_addr_str, 16)

                    file_obj = readSU("struct file", file_addr)

                    if file_obj.f_op == bpf_prog_fops_addr:
                        prog_addr = int(file_obj.private_data)
                        prog_to_process[prog_addr] = (pid, comm)
            except:
                continue

    except:
        pass

    return prog_to_process


def show_bpf_tree(options):
    if not symbol_exists("bpf_tree"):
        print("BPF not available in this kernel")
        return

    bpf_tree = readSymbol("bpf_tree")
    ksym_offset = member_offset("struct bpf_prog_aux", "ksym")
    count = 0

    # Build process mapping
    prog_to_process = _build_bpf_prog_to_process_map()

    if not options.show_details:
        print("%-6s %-22s %-4s %-4s %-6s %-5s %-22s %s" % (
            "ID", "TYPE", "JIT", "GPL", "FUNCS", "MAPS", "OWNER", "NAME"))
        print("-" * 95)

    # Verify struct bpf_ksym exists before walking the rbtree.
    # It is absent on RHEL7 and early RHEL8 kernels.
    try:
        if member_offset("struct bpf_ksym", "tnode") < 0:
            raise KeyError
    except (KeyError, Exception):
        print("struct bpf_ksym not available in this kernel version")
        return

    for bpf_ksym in for_all_rbtree(bpf_tree.tree[0],
                                   "struct bpf_ksym",
                                   "tnode"):
        try:
            prog_id = 0
            prog_name = ""
            prog_type = 0
            prog = None
            jited = 0
            gpl_compatible = 0
            func_cnt = 0
            map_cnt = 0
            stack_depth = 0
            prog_tag = ""

            if ksym_offset >= 0:
                aux = readSU("struct bpf_prog_aux",
                             int(bpf_ksym) - ksym_offset)
                try:
                    prog_id = aux.id
                except:
                    pass
                try:
                    raw = bpf_ksym.name
                    prog_name = raw.decode("utf-8", errors="replace").rstrip("\x00") if isinstance(raw, bytes) else str(raw).rstrip("\x00")
                except:
                    prog_name = ""
                if not prog_name:
                    try:
                        raw = aux.name
                        if isinstance(raw, bytes):
                            prog_name = raw.decode("utf-8", errors="replace").rstrip("\x00")
                        else:
                            prog_name = str(raw).rstrip("\x00")
                    except:
                        prog_name = ""
                try:
                    func_cnt = aux.func_cnt
                except:
                    pass
                try:
                    stack_depth = aux.stack_depth
                except:
                    pass
                try:
                    map_cnt = aux.used_map_cnt
                except:
                    pass
                try:
                    prog = aux.prog
                    prog_type = prog.type
                    jited = prog.jited
                    gpl_compatible = prog.gpl_compatible
                    try:
                        prog_tag = "".join("%02x" % b for b in prog.tag[:8])
                    except:
                        pass
                except:
                    pass
            else:
                # Fallback: derive name from bpf_ksym only
                try:
                    raw = bpf_ksym.name
                    prog_name = raw.decode("utf-8", errors="replace").rstrip("\x00") if isinstance(raw, bytes) else str(raw)
                except:
                    prog_name = ""

            # Get process owner (name + PID)
            owner = ""
            if prog is not None and int(prog) in prog_to_process:
                pid, comm = prog_to_process[int(prog)]
                owner = "%s(%d)" % (comm, pid)
            if not owner:
                # Fallback to aux.name if process not found
                try:
                    if ksym_offset >= 0:
                        raw = aux.name
                        if raw:
                            name_str = raw.decode("utf-8", errors="replace").rstrip("\x00") if isinstance(raw, bytes) else str(raw).rstrip("\x00")
                            if name_str.strip():
                                owner = name_str.strip()
                except:
                    pass

                if not owner:
                    owner = "-"

            type_str = _bpf_prog_type_str(prog_type)
            color = _bpf_prog_color(prog_type)

            # Skip invalid xarray entries (corrupted data from tagged pointers)
            # - prog_id == 0: uninitialized entries
            # - prog_id > 1000000: corrupted memory addresses appearing as IDs
            # - prog_type == 0: BPF_PROG_TYPE_UNSPEC (invalid)
            # - func_cnt > 256: exceeds BPF_MAX_SUBPROGS (include/linux/bpf_verifier.h)
            # - map_cnt > 64: exceeds MAX_USED_MAPS (include/linux/bpf_verifier.h)
            if (prog_id == 0 or
                prog_id > 1000000 or
                prog_type == 0 or
                func_cnt > 256 or
                map_cnt > 64):
                continue

            if options.filter_ids and prog_id not in options.filter_ids:
                continue

            if not options.show_details:
                crashcolor.set_color(color)
                print("%-6d %-22s %-4s %-4s %-6d %-5d %-22s %s" % (
                    prog_id, type_str[:22],
                    "yes" if jited else "no",
                    "yes" if gpl_compatible else "no",
                    func_cnt, map_cnt, owner[:22], prog_name))
                crashcolor.set_color(crashcolor.RESET)
            else:
                crashcolor.set_color(color)
                if options.debug:
                    print("BPF Program ID: %-6d (aux.id)    addr: struct bpf_ksym 0x%x" % (prog_id, int(bpf_ksym)))
                else:
                    print("BPF Program ID: %-6d  addr: 0x%x" % (prog_id, int(bpf_ksym)))
                crashcolor.set_color(crashcolor.RESET)
                if options.debug and ksym_offset >= 0:
                    bpf_prog_aux_addr = int(bpf_ksym) - ksym_offset
                    print("  bpf_prog_aux  : 0x%x" % bpf_prog_aux_addr)
                    if prog is not None:
                        print("  bpf_prog      : 0x%x" % int(prog))
                if options.debug:
                    print("  Name          : %s (aux.name / ksym.name)" % prog_name)
                else:
                    print("  Name        : %s" % prog_name)
                print("  Owner       : %s" % owner)
                print("  Type        : %s (%d)" % (type_str, prog_type))
                print("  JIT compiled: %s" % ("yes" if jited else "no"))
                print("  GPL compat  : %s" % ("yes" if gpl_compatible else "no"))
                print("  Func count  : %d" % func_cnt)
                print("  Stack depth : %d" % stack_depth)
                if prog_tag:
                    print("  Tag         : %s" % prog_tag)

                # Suppress crash/gdb symbol lookup warnings when accessing start/end addresses
                import os
                old_stderr = os.dup(2)
                old_stdout = os.dup(1)
                devnull = os.open('/dev/null', os.O_WRONLY)
                os.dup2(devnull, 2)
                os.dup2(devnull, 1)

                try:
                    start_addr = bpf_ksym.start
                    end_addr = bpf_ksym.end
                finally:
                    os.dup2(old_stdout, 1)
                    os.dup2(old_stderr, 2)
                    os.close(old_stdout)
                    os.close(old_stderr)
                    os.close(devnull)

                if options.debug:
                    print("  Range       : 0x%x - 0x%x (ksym.start - ksym.end)" % (start_addr, end_addr))
                else:
                    print("  Range       : 0x%x - 0x%x" % (start_addr, end_addr))
                if options.disasm and start_addr and end_addr and start_addr < end_addr:
                    print("\n  === Disassembled Code ===")
                    try:
                        # Use a large instruction count to cover the full range
                        # crash's dis will automatically stop at invalid memory (end of BPF program)
                        instruction_count = 10000

                        # Suppress crash warnings by redirecting stderr during dis command
                        import os
                        old_stderr = os.dup(2)
                        devnull = os.open('/dev/null', os.O_WRONLY)
                        os.dup2(devnull, 2)

                        try:
                            dis_output = exec_crash_command("dis 0x%x %d" % (start_addr, instruction_count))
                        finally:
                            os.dup2(old_stderr, 2)
                            os.close(old_stderr)
                            os.close(devnull)

                        # Collect valid disassembly lines (skip all warnings and errors)
                        lines = []
                        for line in dis_output.strip().split('\n'):
                            if 'WARNING:' in line:
                                continue
                            if 'dis: invalid kernel virtual address' in line:
                                continue
                            if line.strip():
                                lines.append(line)

                        # Trim trailing int3 padding instructions (keep first one as end-of-code marker)
                        while len(lines) > 1 and 'int3' in lines[-1]:
                            lines.pop()

                        # Print cleaned output
                        for line in lines:
                            print("  " + line)
                    except Exception as e:
                        print("  (Unable to disassemble: %s)" % str(e))
                    print("  === End Disassembly ===\n")
                if map_cnt > 0 and ksym_offset >= 0:
                    print("  Maps (%d):" % map_cnt)
                    try:
                        for i in range(map_cnt):
                            bpf_map = aux.used_maps[i]
                            if bpf_map:
                                map_name = ""
                                map_type = 0
                                map_id = 0
                                try:
                                    raw = bpf_map.name
                                    map_name = raw.decode("utf-8", errors="replace").rstrip("\x00") if isinstance(raw, bytes) else str(raw).rstrip("\x00")
                                except:
                                    pass
                                try:
                                    map_type = bpf_map.map_type
                                except:
                                    pass
                                try:
                                    map_id = bpf_map.id
                                except:
                                    pass
                                if options.debug:
                                    print("    [%d] ID:%-5d (map.id)  %-20s (map.map_type)  struct bpf_map 0x%x  %s (map.name)" % (
                                        i, map_id,
                                        _bpf_map_type_str(map_type)[:20],
                                        int(bpf_map),
                                        map_name))
                                else:
                                    print("    [%d] ID:%-5d %-22s %s" % (
                                        i, map_id,
                                        _bpf_map_type_str(map_type)[:22],
                                        map_name))
                    except:
                        pass
                print()

            count += 1
        except Exception as e:
            print(e)

    if options.filter_ids:
        print("Showing %d programs (filtered by ID: %s)" % (
            count, ",".join(str(i) for i in sorted(options.filter_ids))))
    else:
        print("Total BPF programs: %d" % count)



def traceinfo():
    op = OptionParser()
    op.add_option("-b", "--bpf_tree", dest="bpf_tree", default=0,
                  action="store_true",
                  help="Show bpf_tree list")

    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show details")

    op.add_option("-m", "--trace_modules", dest="show_trace_modules", default=0,
                  action="store_true",
                  help="Show modules involved in ftrace")

    op.add_option("-t", "--trace_types", dest="show_trace_types", default=0,
                  action="store_true",
                  help="Show ftrace types")

    op.add_option("-D", "--debug", dest="debug", default=False,
                  action="store_true",
                  help="show structure names and field sources in detailed output")

    op.add_option("--disasm", "--asm", dest="disasm", default=False,
                  action="store_true",
                  help="show disassembled BPF program code in detailed output (use with -d)")

    op.add_option("-i", "--ip", dest="ip_addr", default="",
                  action="store", type="string",
                  help="Look up kprobe for a specific IP address (hex, e.g. 0xffffffff...)")

    (o, args) = op.parse_args()

    # Parse optional BPF Program ID filter
    filter_ids = set()
    if len(args) > 0:
        try:
            id_str = args[0]
            filter_ids = set(int(x.strip()) for x in id_str.split(','))
        except:
            pass
    o.filter_ids = filter_ids

    if o.ip_addr:
        try:
            ip_addr = int(o.ip_addr, 16) if o.ip_addr.startswith("0x") else int(o.ip_addr, 0)
            show_kprobe_by_ip(o, ip_addr)
        except ValueError:
            print("Invalid IP address: %s (expected hex, e.g. 0xffffffff...)" % o.ip_addr)
        sys.exit(0)

    if o.bpf_tree:
        show_bpf_tree(o)
        sys.exit(0)

    if o.show_trace_types:
        show_trace_types(o)
        sys.exit(0)

    if o.show_trace_modules:
        show_trace_modules(o)
        sys.exit(0)

    show_ftrace_list(o)


if ( __name__ == '__main__'):
    traceinfo()
