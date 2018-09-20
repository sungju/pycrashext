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
import pstree
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
xtime = None


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
    global xtime

    runtime = task_struct.se.sum_exec_runtime
    start_time = task_struct.start_time.tv_sec
    stime = start_time
    if timekeeper == None:
        timekeeper = readSymbol("timekeeper")

    if xtime == None:
        if member_offset('struct timekeeper', 'xtime') > -1:
            xtime = timekeeper.xtime
        else:
            xtime = readSymbol("xtime")

    if member_offset("struct timekeeper", "raw_time") > -1:
        stime = timekeeper.raw_time.tv_sec - stime
    else:
        if member_offset("struct timekeeper", "wall_to_monotonic") > -1:
            wall_to_monotonic = timekeeper.wall_to_monotonic
        else:
            wall_to_monotonic = readSymbol("wall_to_monotonic")

        adjusted_val = xtime.tv_sec + wall_to_monotonic.tv_sec
        stime = adjusted_val - stime

    return display_date(xtime.tv_sec - stime, xtime.tv_sec), convert_sec_to_str(stime)


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
    if pstree.get_thread_count(task_struct) > 0 and \
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
        pid_data["%CPU"] = "n/a"
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

    (o, args) = op.parse_args()

    if (o.aux):
        print(get_ps_aux())
        sys.exit(0)

    if (o.auxcww):
        print(get_ps_auxcww())
        sys.exit(0)

    if (o.auxww):
        print(get_ps_auxww())
        sys.exit(0)

    print(get_ps_ef())


if ( __name__ == '__main__'):
    psinfo()
