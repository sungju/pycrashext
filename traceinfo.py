"""
 Written by Daniel Sungju Kwon
"""
from pykdump.API import *

from LinuxDump import Tasks

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


def print_handler(tab_str, handler_type, handler_addr, kp):
    if handler_addr != 0:
        handler_name = addr2sym(handler_addr)
        mod_name = get_module_name(handler_name)
        print("\t%s%s_handler = 0x%x (%s)%s" % (tab_str, handler_type, handler_addr, handler_name,
                                                mod_name))
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




def print_handler_handler(handler_type, kprobe):
    for kp in readSUListFromHead(kprobe.list,
                                "list",
                                "struct kprobe"):
        if handler_type == "pre":
            print_handler("\t", handler_type, kp.pre_handler, kp)
        elif handler_type == "post":
            print_handler("\t", handler_type, kp.post_handler, kp)
        elif handler_type == "fault":
            print_handler("\t", handler_type, kp.fault_handler, kp)
        elif handler_type == "break":
            print_handler("\t", handler_type, kp.break_handler, kp)
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


def show_ftrace_list(options):
    kprobe_table_list = readSymbol("kprobe_table")
    tp_offset = member_offset("struct trace_probe", "rp")
    tp_offset = tp_offset + member_offset("struct kretprobe", "kp")
    for hh in kprobe_table_list:
        for kprobe in hlist_for_each_entry("struct kprobe", hh, "hlist"):
            print("struct kprobe 0x%x" % (kprobe))
            if kprobe.addr != 0:
                print("\taddr = 0x%x (%s)" % (kprobe.addr, addr2sym(kprobe.addr)))
            print_handler("", "pre", kprobe.pre_handler, kprobe)
            print_handler_handler("pre", kprobe)
            print_handler("", "post", kprobe.post_handler, kprobe)
            print_handler_handler("post", kprobe)
            print_handler("", "fault", kprobe.fault_handler, kprobe)
            print_handler_handler("fault", kprobe)
            print_handler("", "break", kprobe.break_handler, kprobe)
            print_handler_handler("break", kprobe)
            if options.show_details:
                trace_probe = readSU("struct trace_probe", kprobe - tp_offset)
                print("\t\tflags : %s" % (kprobe_flags_str(trace_probe.flags)))
                print("\t\tcall.name = '%s'" % (trace_probe.call.name))


    if options.show_details:
        ftrace_events_list = readSymbol("ftrace_events")
        print("\nftrace_events")
        count = 0
        for ftrace_event_call in readSUListFromHead(ftrace_events_list,
                                                    "list",
                                                    "struct ftrace_event_call"):
            print("\t0x%x: name = %s" % (ftrace_event_call, ftrace_event_call.name))
            count = count + 1

        print("\n\ttotal event : %d" % (count))


    global_trace = readSymbol("global_trace")
    print("\n")
    if (global_trace.buffer_disabled == 0 and
        global_trace.trace_buffer.buffer.record_disabled.counter == 0):
        print("** ftrace Enabled (struct trace_array 0x%x)" % global_trace)
        current_trace = global_trace.current_trace
        print("current_tracer = '%s' (struct tracer 0x%x)" % (current_trace.name, current_trace))
    else:
        print("** ftrace Disabled")

def traceinfo():
    op = OptionParser()
    op.add_option("-d", "--details", dest="show_details", default=0,
                  action="store_true",
                  help="Show details")

    (o, args) = op.parse_args()

    show_ftrace_list(o)


if ( __name__ == '__main__'):
    traceinfo()
