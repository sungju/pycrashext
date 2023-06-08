"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

from LinuxDump import Tasks

import sys
import operator

import crashcolor
import epstree
import crashhelper
from datetime import datetime, timedelta


is_userdata_avail = False


def get_tty_name(task_struct):
    tty = task_struct.signal.tty
    if tty == 0 or tty == None:
        return "?"

    return tty.name


def get_uid(task_struct):
    try:
        val = task_struct.loginuid.val
    except:
        val = task_struct.loginuid

    if val == -1 or val == 4294967295:
        val = 0

    if val == 0:
        return "root"
    return "%d" % val


def get_uid_from_task(task_struct):
    global is_userdata_avail

    if is_userdata_avail == False or task_struct.mm == 0:
        return get_uid(task_struct)

    resultlines = exec_crash_command("ps -a %d" % (task_struct.pid)).splitlines()
    for line in resultlines:
        words = line.split("=")
        if words[0] == 'USER':
            return words[1]

    return get_uid(task_struct)


timekeeper = None
xtime_sec = None


def get_datetime(nsec):
    if nsec < 0:
        nsec = 0
    sec = timedelta(seconds=nsec)
    d = datetime(1,1,1) + sec

    return d


def display_date(nsec, cur_nsec):
    d = get_datetime(nsec)
    curr_d = get_datetime(cur_nsec)
    if d.year == curr_d.year:
        if d.month == curr_d.month:
            if d.day == curr_d.day:
                return "%02d:%02d:%02d" % (d.hour, d.minute, d.second)
    else:
        return datetime.fromtimestamp(nsec).strftime('%c')

    return "%s%s" % (d.strftime("%B")[:3], d.day)


def convert_sec_to_str(nsec):
    d = get_datetime(nsec)
    days = nsec/(60*60*24)

    return "%4d,%02d:%02d:%02d" % (days, d.hour, d.minute, d.second)


intervals = (
    ('weeks', 604800),  # 60 * 60 * 24 * 7
    ('days', 86400),    # 60 * 60 * 24
    ('hours', 3600),    # 60 * 60
    ('minutes', 60),
    ('seconds', 1),
    )

def display_time(seconds, granularity=2):
    result = []

    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            if value == 1:
                name = name.rstrip('s')
            result.append("{} {}".format(value, name))
    return ', '.join(result[:granularity])


def get_time_from_task(task_struct):
    global timekeeper
    global xtime_sec

    runtime = task_struct.se.sum_exec_runtime
    try:
        start_time = task_struct.start_time.tv_sec
    except:
        start_time = task_struct.start_time / 1000000000

    stime = start_time
    if timekeeper == None:
        try:
            tk_core = readSymbol("tk_core")
            timekeeper = tk_core.timekeeper
        except:
            timekeeper = readSymbol("timekeeper")

    if xtime_sec == None:
        if member_offset('struct timekeeper', 'xtime') > -1:
            xtime_sec = timekeeper.xtime.tv_sec
        elif member_offset('struct timekeeper', 'xtime_sec') > -1:
            xtime_sec = timekeeper.xtime_sec
        else:
            try:
                xtime_sec = readSymbol("xtime").tv_sec
            except:
                xtime_sec = 0

    if member_offset("struct timekeeper", "raw_time") > -1:
        stime = timekeeper.raw_time.tv_sec - stime
    else:
        if member_offset("struct timekeeper", "wall_to_monotonic") > -1:
            wall_to_monotonic = timekeeper.wall_to_monotonic
        else:
            wall_to_monotonic = readSymbol("wall_to_monotonic")

        adjusted_val = xtime_sec + wall_to_monotonic.tv_sec
        stime = adjusted_val - stime

    return display_date(xtime_sec - stime, xtime_sec), convert_sec_to_str(stime)


def convert_state(state):
    return {
        'RU': "R",
        'UN': "D",
        'IN': "S",
        'ST': "T",
        'WA': "R", # Kinds of
        'DE': 'X',
        'ZO': 'Z',
    }.get(state, "Z")


def convert_to_ps_state(state, task_struct):
    st = convert_state(state)
    if task_struct.sessionid == task_struct.tgid:
        st = st + "s"  # is a session leader
    if epstree.get_thread_count(task_struct) > 0 and \
       task_struct == task_struct.group_leader: # Compare the address
        st = st + "l"

    return st


def get_comm_args(task_struct):
    resultlines = exec_crash_command("ps -a %d" % (task_struct.pid)).splitlines()
    for line in resultlines:
        words = line.split(':')
        if words[0] == "ARG":
            arg_line = line[line.find(words[1]):]
            return arg_line

    return task_struct.comm


ps_G_output_lines = None

def get_ps_output():
    '''
       PID    PPID  CPU       TASK        ST  %MEM     VSZ    RSS  COMM
    '''
    global ps_G_output_lines

    check_userdata_available()

    if ps_G_output_lines == None:
        ps_G_output_lines = exec_crash_command("ps -G").splitlines()
    iterlines = iter(ps_G_output_lines)
    next(iterlines)
    ps_list = []
    exec_crash_command("kmem -i") # This is here to prevent exec_crash_command bug
    for pid in iterlines:
        words = pid.split()
        pid_data = {}
        if (words[0] == '>'):
            idx = 1
        else:
            idx = 0

        pid_data["PID"] = int(words[idx + 0])
        pid_data["PPID"] = int(words[idx + 1])
        pid_data["CPU"] = int(words[idx + 2])
        pid_data["TASK"] = words[idx + 3]
        task_struct = readSU("struct task_struct", int(pid_data["TASK"], 16))
        pid_data["ST"] = convert_to_ps_state(words[idx + 4], task_struct)
        pid_data["%MEM"] = float(words[idx + 5])
        pid_data["%CPU"] = 0  # "n/a"
        pid_data["C"] = "0" # n/a
        pid_data["TTY"] = get_tty_name(task_struct)
        pid_data["VSZ"] = int(words[idx + 6])
        pid_data["RSS"] = int(words[idx + 7])
        pid_data["COMM"] = pid[pid.find(words[idx + 8]):]
        if is_userdata_avail == True and task_struct.mm != 0:
            pid_data["COMM"] = get_comm_args(task_struct)

        pid_data["UID"] = get_uid_from_task(task_struct)
        stime, runtime = get_time_from_task(task_struct)
        pid_data["STIME"] = stime
        pid_data["TIME"] = runtime

        ps_list.append(pid_data)

    return ps_list


def get_ps():
    ps_list = get_ps_output()
    result_str = "%-12s %8s %4s %4s %8s %8s %-8s %-5s %10s %8s %s\n" % \
                ("USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY", "STAT",\
                 "START", "TIME", "COMMAND")

    for task in ps_list:
        try:
            result_str = result_str + \
                    "%-12s %8s %4s %4s %8s %8s %-8s %-5s %10s %8s %s\n" % \
                  (task["UID"], task["PID"], task["%CPU"], task["%MEM"], \
                   task["VSZ"], task["RSS"], task["TTY"], task["ST"], \
                   task["STIME"], task["TIME"], task["COMM"])
        except Exception as e:
            print(e)
            break

    return result_str


def get_ps_aux():
    '''
    USER        PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
    root          1  0.0  0.0 128268  6956 ?        Ss   Aug21   4:21 /usr/lib/systemd/systemd --switch
    root          2  0.0  0.0      0     0 ?        S    Aug21   0:02 [kthreadd]
    '''

    return get_ps()


def get_ps_auxcww():
    '''
    USER        PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
    root          1  0.0  0.0 128268  6956 ?        Ss   Aug21   4:21 systemd
    root          2  0.0  0.0      0     0 ?        S    Aug21   0:02 kthreadd
    '''
    return get_ps()


def get_ps_auxww():
    '''
    USER        PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
    root          1  0.0  0.0 128268  6956 ?        Ss   Aug21   4:21 /usr/lib/systemd/systemd --switched-root --system --deserialize 22
    root          2  0.0  0.0      0     0 ?        S    Aug21   0:02 [kthreadd]
    '''
    return get_ps()


def get_ps_ef():
    '''
    UID         PID   PPID  C STIME TTY          TIME CMD
    root          1      0  0 Aug21 ?        00:04:21 /usr/lib/systemd/systemd --switched-root --system
    root          2      0  0 Aug21 ?        00:00:02 [kthreadd]
    '''
    ps_list = get_ps_output()
    result_str = "%-12s %8s %8s %2s %8s %8s %8s %s\n" % \
                ("UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD")


    for task in ps_list:
        try:
            result_str = result_str + \
                    "%-12s %8s %8s %2s %8s %8s %8s %s\n" % \
                    (task["UID"], task["PID"], task["PPID"], \
                     task["C"], task["STIME"], task["TTY"], \
                     task["TIME"], task["COMM"])
        except Exception as e:
            print(e)
            break

    return result_str


def check_userdata_available():
    global is_userdata_avail

    is_userdata_avail = True
    resultlines = exec_crash_command("help -D").splitlines()
    for line in resultlines:
        words = line.strip().split(':')
        if words[0] == 'dump_level':
            if line.find('EXCLUDE_USER_DATA') > -1:
                is_userdata_avail = False

            break


def get_policy_str(policy):
    return {
        0: "NORMAL",
        1: "FIFO",
        2: "RR",
        3: "BATCH",
        4: "ISO",
        5: "IDLE",
        6: "DEADLINE",
    } [policy]


def task_policy(policy_str):
    return {
        "SCHED_OTHER": 0,
        "NORMAL": 0,
        "0": 0,
        "SCHED_FIFO" : 1,
        "FIFO" : 1,
        "1" : 1,
        "SCHED_RR" : 2,
        "RR" : 2,
        "2" : 2,
        "SCHED_BATCH" : 3,
        "BATCH" : 3,
        "3" : 3,

        "SCHED_ISO" : 4,
        "ISO" : 4,
        "4" : 4,

        "SCHED_IDLE" : 5,
        "IDLE" : 5,
        "5" : 5,
        "SCHED_DEADLINE" : 6,
        "DEADLINE" : 6,
        "6" : 6,
    }[policy_str.upper()]


dl_util_percent = 0
dl_util_calc_str = ""

def init_policy_data():
    global dl_util_percent
    global dl_util_calc_str

    dl_util_percent = 0
    dl_util_calc_str = ""


def get_policy_sched_other(task_struct):
    return "static_prio = %d, normal_prio = %d, prio = %d" % \
            (task_struct.static_prio, task_struct.normal_prio, task_struct.prio)


def get_policy_sched_fifo(task_struct):
    return "rt_priority = %d" % (task_struct.rt_priority)


def get_policy_sched_rr(task_struct):
    return get_policy_sched_fifo(task_struct)


def get_policy_sched_deadline(task_struct):
    global dl_util_percent
    global dl_util_calc_str

    sched_dl = task_struct.dl
    if len(dl_util_calc_str) > 0:
        dl_util_calc_str = dl_util_calc_str + " + "

    dl_util_calc_str = dl_util_calc_str + ("%d/%d" % (sched_dl.dl_runtime, sched_dl.dl_period))
    dl_util_percent = dl_util_percent + \
            (sched_dl.dl_runtime / sched_dl.dl_period) * 100

    return "runtime = %d us, period = %d us, deadline = %d us" % \
            (sched_dl.dl_runtime / 1000, sched_dl.dl_period / 1000, sched_dl.dl_deadline / 1000)


def get_policy_details(task_struct):
    policy = task_struct.policy
    if (policy == 0):
        return get_policy_sched_other(task_struct)
    elif (policy == 1):
        return get_policy_sched_fifo(task_struct)
    elif (policy == 2):
        return get_policy_sched_rr(task_struct)
    elif (policy == 6):
        return get_policy_sched_deadline(task_struct)
    else:
        return ""


def get_policy_summary_other():
    return ""


def get_policy_summary_fifo():
    return ""


def get_policy_summary_rr():
    return ""


def get_policy_summary_deadline():
    return "SCHED_DEADLINE utilization = %s = %d%%" % (dl_util_calc_str, dl_util_percent)


def get_policy_summary(policy_no):
    if policy_no == 0:
        return get_policy_summary_other()
    elif policy_no == 1:
        return get_policy_summary_fifo()
    elif policy_no == 2:
        return get_policy_summary_rr()
    elif policy_no == 6:
        return get_policy_summary_deadline()
    else:
        return ""


def processes_with_policy(policy_no):
    if policy_no < 0 or policy_no > 6:
        return "Invalid policy number : %d" % (policy_no)

    init_policy_data()

    resultlines = exec_crash_command("ps -y %d" % (policy_no)).splitlines()
    result_str = ""
    for line_str in resultlines[1:]:
        words = line_str.split()
        if words[0] == ">":
            task_addr = words[4]
        else:
            task_addr = words[3]
        task_struct = readSU("struct task_struct", int(task_addr, 16))
        policy_based_str = get_policy_details(task_struct)
        result_str = result_str + "0x%s %s %s %s\n" % (task_addr, task_struct.pid, task_struct.comm, policy_based_str)

    if len(result_str) > 0:
        result_str = result_str + get_policy_summary(policy_no)


    if len(result_str) > 0:
        result_str = "task_struct        PID    COMM\t\tpolicy details\n" + result_str
    return result_str


def search_one_task(bt_str, include_list, exclude_list):
    for exclude_str in exclude_list:
        if exclude_str != '' and bt_str.find(exclude_str) >= 0:
            return False
    for include_str in include_list:
        if include_str != '' and bt_str.find(include_str) >= 0:
            return True

    return False


highlight_color_list = [
    crashcolor.get_color(crashcolor.LIGHTRED),
    crashcolor.get_color(crashcolor.LIGHTBLUE),
    crashcolor.get_color(crashcolor.LIGHTYELLOW),
    crashcolor.get_color(crashcolor.LIGHTMAGENTA),
    crashcolor.get_color(crashcolor.LIGHTCYAN),
]

def print_bt_search(bt_str, include_list):
    reset_color = crashcolor.get_color(crashcolor.RESET)
    reset_len = len(reset_color)
    bt_str_list = bt_str.splitlines()
    highlight_len_list = []
    for hc_str in highlight_color_list:
        highlight_len_list.append(len(hc_str))
    highlight_max = len(highlight_color_list)

    print("")
    for line in bt_str_list:
        idx = 0
        for include_str in include_list:
            pos = line.find(include_str)
            highlight_color = highlight_color_list[idx]
            highlight_len = highlight_len_list[idx]
            while pos >= 0:
                line = line[:pos] + highlight_color + line[pos:pos + len(include_str)] +\
                        reset_color + line[pos + len(include_str):]
                pos = line.find(include_str, pos + len(include_str) + highlight_len + reset_len)
            idx = idx + 1
            if (idx >= highlight_max):
                idx = 0

        print(line)


def do_searchstack(options, bt_flag):
    tt = Tasks.TaskTable()
    include_list = options.include.split(",")
    exclude_list = options.exclude.split(",")

    for t in tt.allThreads():
        if options.task_name != "" and options.task_name not in t.comm:
            continue
        try:
            stackdata = exec_crash_command("bt -%s %d" % (bt_flag, t.pid))
        except:
            continue
        if search_one_task(stackdata, include_list, exclude_list) == True:
            if options.nodetails == True:
                print("%s" % exec_crash_command("bt %d" % (t.pid)))
            else:
                print_bt_search(stackdata, include_list)


import fsinfo

def show_task_path(task, options):
    exe_file = task.mm.exe_file
    options.file = "0x%x" % (Addr(exe_file))
    fsinfo.show_file_details(options)

def get_pid_namespace(task):
    if member_offset("struct task_struct", "thread_pid") >= 0:
        thread_pid = task.thread_pid
    else:
        return 0 

    return thread_pid.numbers[thread_pid.level].ns


def show_task_details(options):
    task = readSU("struct task_struct", int(options.taskaddr, 16))
    print("%d (%s)" % (task.pid, task.comm))
    print("login id = %s" % ("root" if task.loginuid.val == 4294967295 else task.loginuid.val))
    print("SCHED: %s, PRIORITY: %d" % (get_policy_str(task.policy),
            task.prio if task.policy == 0 else task.rt_priority))
    print("pid_namespace = 0x%x" % (get_pid_namespace(task)))
    if task.mm != 0:
        print("==== Binary Details ====")
        show_task_path(task, options)

    thread = task.thread
    fpu = thread.fpu
    if member_offset("struct fpu", "fpstate") >= 0:
        # struct fpu.fpstate
        if member_offset("struct fpstate", "regs") >= 0:
            if member_offset("union fpregs_state", "fxsave") >= 0:
                print(fpu.fpstate.regs.fxsave)
    elif member_offset("struct fpu", "state") >= 0:
        # struct fpu.state
        if member_offset("union thread_xstate", "fxsave") >= 0:
            print(fpu.state.fxsave)


def psinfo():
    op = OptionParser()
    op.add_option("--aux", dest="aux", default=0,
                  action="store_true",
                  help="ps aux")
    op.add_option("--auxcww", dest="auxcww", default=0,
                  action="store_true",
                  help="ps auxcww")
    op.add_option("--auxww", dest="auxww", default=0,
                  action="store_true",
                  help="ps auxww")
    op.add_option("--ef", dest="ef", default=0,
                  action="store_true",
                  help="ps -ef")
    op.add_option("-p", "--policy", dest="policy_type", default="",
                  type="string",
                  action="store",
                  help="Shows specific policy type of processes only. "
                        "0 : NORMAL, 1 : FIFO, 2 : RR, 3 : BATCH, "
                        "5 : IDLE, 6 : DEADLINE")
    op.add_option("-s", "--searchstack", dest="searchstack", default=0,
                  action="store_true",
                  help="Search each task stack to find value specified in include with 'bt -f'")
    op.add_option("-S", "--Searchstack", dest="Searchstack", default=0,
                  action="store_true",
                  help="Search each task stack to find value specified in include with 'bt -F'")
    op.add_option("-n", "--nodetails", dest="nodetails", default=0,
                  action="store_true",
                  help="Shows no stack contents")
    op.add_option("-i", "--include", dest="include", default="",
                  type="string",
                  action="store",
                  help="comma separated value list to search with --searchstack")
    op.add_option("-e", "--exclude", dest="exclude", default="",
                  type="string",
                  action="store",
                  help="comma separated value list to ignore in --searchstack")

    op.add_option("-k", "--taskname", dest="task_name", default="",
                  action="store", type="string",
                  help="limit search range only to tasks with matching task name")

    op.add_option("-t", "--task", dest="taskaddr", default="",
                  action="store", type="string",
                  help="Shows general information about a task")

    (o, args) = op.parse_args()


    if (o.searchstack):
        do_searchstack(o, "f")
        sys.exit(0)

    if (o.Searchstack):
        do_searchstack(o, "F")
        sys.exit(0)

    if (o.aux):
        print(get_ps_aux())
        sys.exit(0)

    if (o.auxcww):
        print(get_ps_auxcww())
        sys.exit(0)

    if (o.auxww):
        print(get_ps_auxww())
        sys.exit(0)

    if (o.policy_type != ""):
        print(processes_with_policy(task_policy(o.policy_type)))
        sys.exit(0)

    if (o.taskaddr != ""):
        show_task_details(o)
        sys.exit(0)

    print(get_ps_ef())


if ( __name__ == '__main__'):
    psinfo()
