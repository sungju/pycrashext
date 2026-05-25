from pykdump.API import *
from LinuxDump import Tasks

import crashcolor

from datetime import datetime

def parse_task_info(line):
    try:
        idx = line.index("]")
    except:
        idx = -1

    if idx == -1:
        return None, None
    run_time = line[1:idx].strip()
    days_str, time_str = run_time.split()
    dto = datetime.strptime(time_str, "%H:%M:%S.%f")

    date_info = (int(days_str), dto.hour, dto.minute, dto.second, dto.microsecond)
    return date_info, line[idx + 1:]


ru_task_list = []
in_task_list = []
un_task_list = []
zo_task_list = []
ot_task_list = []

def get_task_list(options, args):
    global ru_task_list
    global in_task_list
    global un_task_list
    global zo_task_list
    global ot_task_list

    result = exec_crash_command("ps -m")

    ru_task_list.clear()
    in_task_list.clear()
    un_task_list.clear()
    zo_task_list.clear()
    ot_task_list.clear()

    for line in result.splitlines():
        runtime_info, rest_str = parse_task_info(line)
        if rest_str == None:
            continue
        words = rest_str.split()
        task_data = {"runtime" : runtime_info, "data" : words, "raw" : line}
        if words[0] == "[RU]":
            ru_task_list.append(task_data)
        elif words[0] == "[IN]":
            in_task_list.append(task_data)
        elif words[0] == "[UN]":
            un_task_list.append(task_data)
        elif words[0] == "[ZO]":
            zo_task_list.append(task_data)
        else:
            ot_task_list.append(task_data)

def get_useconds(dto):
    days, hours, minutes, seconds, useconds = dto
    return useconds + (seconds * 1000000) + (minutes * 60 * 1000000) + (hours * 60 * 60 * 1000000) + (days * 24 * 60 * 60 * 1000000)


def getKey(taskObj):
    dto = taskObj["runtime"]
    return get_useconds(dto)


def get_task_policy_str(policy):
    try:
        return {
            0: "NORMAL", # SCHED_NORMAL
            1: "FIFO", # SCHED_FIFO
            2: "RR", # SCHED_RR
            3: "BATCH", # SCHED_BATCH
            5: "IDLE", # SCHED_IDLE
            6: "DEADLINE", # SCHED_DEADLINE
        }[policy]
    except:
        return "??"


def get_task_wchan(pid):
    """Return the top kernel stack symbol for a task (wchan equivalent)."""
    try:
        for line in exec_crash_command("bt %s" % pid).splitlines():
            line = line.strip()
            if line.startswith("#0 "):
                parts = line.split()
                # Format: "#0 [addr] symbol at addr" or "#0 [addr] symbol"
                for i, p in enumerate(parts):
                    if p == "at" and i > 0:
                        return parts[i - 1]
                if len(parts) >= 3:
                    return parts[2]
    except Exception:
        pass
    return "?"


def get_task_uid_str(task):
    """Return UID string, falling back from loginuid to effective uid."""
    try:
        val = task.loginuid.val
    except Exception:
        val = 0xffffffff

    if val == 0xffffffff or val == 4294967295:
        # loginuid not set (AUDIT_UID_UNSET) — use effective uid
        try:
            val = task.cred.uid.val
        except Exception:
            val = 0

    return "root" if val == 0 else str(val)


def show_task_details(taskObj):
    pid = taskObj["data"][2]
    task = readSU("struct task_struct", int(taskObj["data"][4], 16))
    wchan = get_task_wchan(pid)
    print("\tpolicy = %s, priority = %d, UID = %s, wchan = %s" %
          (get_task_policy_str(task.policy),
           task.prio if task.policy == 0 else task.rt_priority,
           get_task_uid_str(task), wchan))


def show_task_files(taskObj):
    task = readSU("struct task_struct", int(taskObj["data"][4], 16))
    fdt = task.files.fdt
    max_fds = fdt.max_fds
    fds = fdt.fd
    first = 1
    for i in range(0, max_fds):
        if fds[i] > 0:
            file_addr = readULong(fds[i])
            file = readSU("struct file", file_addr)
            info = exec_crash_command("files -d 0x%x" % (file.f_path.dentry)).splitlines()
            if first == 1:
                print("\t%s" % (info[0]))
                first = 0
            print("\t%s" % (info[1]))


DEFAULT_MAX_TASKS = 5


def show_task_state_summary():
    """Print a one-line count of tasks in each state."""
    print("Task state summary: RU=%d, IN=%d, UN=%d, ZO=%d, Other=%d" % (
        len(ru_task_list), len(in_task_list), len(un_task_list),
        len(zo_task_list), len(ot_task_list)))
    print("")


def show_zombie_tasks():
    """Display zombie (ZO) processes if any exist."""
    if not zo_task_list:
        return
    print("=" * 60)
    print("Zombie processes (%d):" % len(zo_task_list))
    print("=" * 60)
    for taskObj in zo_task_list:
        crashcolor.set_color(crashcolor.MAGENTA)
        print(taskObj["raw"])
        crashcolor.set_color(crashcolor.RESET)
    print("")


def hangcheck_display(options, args):
    get_task_list(options, args)

    hung_task_timeout_usecs = readSymbol("sysctl_hung_task_timeout_secs") * 1000000
    threshold_usecs = getattr(options, 'threshold', 0) * 1000000

    show_task_state_summary()

    print("hung_task_timeout_secs = %d" % (hung_task_timeout_usecs / 1000000))
    print("")

    task_list_sorted = sorted(un_task_list, key=getKey, reverse=False)

    # Apply minimum duration filter (-t)
    if threshold_usecs > 0:
        task_list_sorted = [t for t in task_list_sorted
                            if get_useconds(t["runtime"]) >= threshold_usecs]

    total_count = len(task_list_sorted)

    # Count hung tasks across the full list for the summary line
    hung_task_count = sum(
        1 for t in task_list_sorted
        if get_useconds(t["runtime"]) >= hung_task_timeout_usecs
    )

    # Limit display to the longest-running tasks unless -a is given
    if not options.all and total_count > DEFAULT_MAX_TASKS:
        skipped = total_count - DEFAULT_MAX_TASKS
        print("<... %d process%s skipped, use -a to show all ...>" %
              (skipped, "es" if skipped > 1 else ""))
        display_list = task_list_sorted[-DEFAULT_MAX_TASKS:]
    else:
        display_list = task_list_sorted

    for taskObj in display_list:
        runtime = get_useconds(taskObj["runtime"])
        if runtime >= hung_task_timeout_usecs * 2:
            crashcolor.set_color(crashcolor.LIGHTRED)
        elif runtime >= hung_task_timeout_usecs:
            crashcolor.set_color(crashcolor.BLUE)

        print(taskObj["raw"])
        if options.detail:
            show_task_details(taskObj)

        if options.files:
            show_task_files(taskObj)

        if getattr(options, 'backtrace', False):
            pid = taskObj["data"][2]
            bt_result = exec_crash_command("bt %s" % pid)
            for bt_line in bt_result.splitlines()[1:]:
                print("\t%s" % bt_line)

        crashcolor.set_color(crashcolor.RESET)

    if total_count > 0:
        print("=" * 60)
        task_s = "s" if total_count > 1 else ""
        task_hung_s = "s" if hung_task_count > 1 else ""
        print("Total %d task%s in D state. %d task%s in D state longer than %d seconds" %
              (total_count, task_s, hung_task_count, task_hung_s,
               hung_task_timeout_usecs / 1000000))

    show_zombie_tasks()


def hangcheck_main():
    op = OptionParser()
    op.add_option("-a", "--all",
                  action="store_true",
                  dest="all",
                  default=False,
                  help="Shows all UN-state processes (default: latest %d)" % DEFAULT_MAX_TASKS)
    op.add_option("-d", "--detail",
                  action="store_true",
                  dest="detail",
                  default=False,
                  help="Shows task details")
    op.add_option("-f", "--files",
                  action="store_true",
                  dest="files",
                  default=False,
                  help="Shows open files in the task")
    op.add_option("-b", "--backtrace",
                  action="store_true",
                  dest="backtrace",
                  default=False,
                  help="Shows kernel backtrace (bt) for each D-state task")
    op.add_option("-t", "--threshold",
                  action="store", type="int",
                  dest="threshold",
                  default=0,
                  help="Only show tasks in D state longer than N seconds")
    (o, args) = op.parse_args()
    hangcheck_display(o, args)


if ( __name__ == '__main__' ):
    hangcheck_main()

