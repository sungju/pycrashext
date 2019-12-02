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
    return {
        0: "NORMAL", # SCHED_NORMAL
        1: "FIFO", # SCHED_FIFO
        2: "RR", # SCHED_RR
        3: "BATCH", # SCHED_BATCH
        5: "IDLE", # SCHED_IDLE
        6: "DEADLINE", # SCHED_DEADLINE
    }[policy]

def show_task_details(taskObj):
    task = readSU("struct task_struct", int(taskObj["data"][4], 16))
    print("\tpolicy = %s, priority = %d, UID = %d" % 
          (get_task_policy_str(task.policy), task.prio if task.policy == 0 else
           task.rt_priority, -1 if task.loginuid.val >= 0xffffffff else task.loginuid.val))


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


def hangcheck_display(options, args):
    get_task_list(options, args)

    hung_task_timeout_usecs = readSymbol("sysctl_hung_task_timeout_secs") * 1000000

    task_list_sorted = sorted(un_task_list, key=getKey, reverse=False)
    hung_task_count = 0
    for taskObj in task_list_sorted:
        runtime = get_useconds(taskObj["runtime"])
        if runtime >= hung_task_timeout_usecs * 2:
            crashcolor.set_color(crashcolor.LIGHTRED)
            hung_task_count = hung_task_count + 1
        elif runtime >= hung_task_timeout_usecs:
            crashcolor.set_color(crashcolor.BLUE)
            hung_task_count = hung_task_count + 1

        print(taskObj["raw"])
        if options.detail == True:
            show_task_details(taskObj)

        if options.files == True:
            show_task_files(taskObj)

        crashcolor.set_color(crashcolor.RESET)


    task_count = len(un_task_list)
    if task_count > 0:
        print("=" * 60)
        task_s = "s" if task_count > 1 else ""
        task_hung_s = "s" if hung_task_count > 1 else ""
        print("Total %d task%s were in D state. %d task%s were in D state longer than %d seconds" %
              (task_count, task_s, hung_task_count, task_hung_s, hung_task_timeout_usecs / 1000000))


def hangcheck_main():
    op = OptionParser()
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
    (o, args) = op.parse_args()
    hangcheck_display(o, args)


if ( __name__ == '__main__' ):
    hangcheck_main()

