"""
 Written by Daniel Sungju Kwon
"""
import sys
import ntpath
import operator
import math

import rules_helper as rh


def is_major():
    return False


def description():
    return "Checking hung tasks"


def add_rule(sysinfo):
    return True


def find_uninterruptible_tasks(ps_list_str):
    ps_list = ps_list_str.splitlines()
    un_list = []
    for pid in ps_list:
        words = pid.split()
        if pid.find("[UN]  PID:") != -1:
            un_list.append(pid)


    sorted_list = sorted(un_list,
                         key=operator.itemgetter(1), reverse=True)

    return sorted_list


def check_system_hang(task_list):
    if task_list is None or len(task_list) == 0:
        return False

    task = task_list[len(task_list) - 1]
    words = task[1:].split()
    days = words[0]
    time_str = words[1][:-1]
    words = time_str.split(':')
    time = int(days) * 24 * 60 * 60 + int(words[0]) * 60 * 60 + \
            int(words[1]) * 60 + math.ceil(float(words[2]))

    hung_task_timeout_secs = rh.get_symbol("sysctl_hung_task_timeout_secs")
    hung_task_panic = rh.get_symbol("sysctl_hung_task_panic")

    if time >= hung_task_timeout_secs:
        return True

    return False


def run_rule(basic_data):
    result = find_uninterruptible_tasks(rh.get_data(basic_data, "ps -m"))
    system_hung = check_system_hang(result)
    if system_hung == False:
        return None

    result_dict = {}
    result_dict["TITLE"] = "hung tasks detected by %s" % \
                            ntpath.basename(__file__)
    min_idx = max(len(result) - 5, 0)
    result_dict["MSG"] = "%s UN tasks\n" % (len(result)) + \
            "%s" % ("...\n" if min_idx > 0 else "") + \
            "\n".join(result[min_idx:])
    result_dict["KCS_TITLE"] = "System becomes unresponsive with message \"INFO: task <process>:<pid> blocked for more than 120 seconds\"."
    result_dict["KCS_URL"] = "https://access.redhat.com/solutions/31453"
    result_dict["RESOLUTION"] = "Please check long blocked tasks.\n" \
            "\tCurrent hung_task_timeout_secs is %d seconds" % \
            (readSymbol("sysctl_hung_task_timeout_secs"))

    return [result_dict]

def hung_task_check():
    import pprint
    pp = pprint.PrettyPrinter(indent=0, width=180)
    pp.pprint(run_rule(None))

if ( __name__ == '__main__'):
    hung_task_check()
