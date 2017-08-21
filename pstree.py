"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

from LinuxDump.Tasks import Task, TaskTable

import sys

class LineType(object):
    LINE_SPACE = 0,
    LINE_FIRST = 1,
    LINE_BRANCH = 2,
    LINE_LAST = 3,
    LINE_VERT = 4


line_type = ["    ", "-+- ", " |- ", " `- ", " |  "]
pid_cnt = 0
branch_bar = []
branch_locations = []

def print_pstree(options):
    global pid_cnt
    pid_cnt = 0
    init_task = readSymbol("init_task")
    if (options.task_id > 0):
        tt = TaskTable()
        init_task = tt.getByPid(options.task_id)
    print_task(init_task, 0, True, options)
    print_children(init_task, 0, options)

    print ("\n\nTotal %s tasks printed" % (pid_cnt))

def task_status_str(status):
    return {
        0: "RU",
        1: "IN",
        2: "UN",
        4: "ST",
        8: "TR",
        16: "ZO",
        32: "DE",
        64: "DE",
    }[status]

def print_branch(depth, first):
    global branch_locations
    global branch_bar

    if (first and depth > 0):
        print ("%s" % (line_type[1]), end='')
        return

    for i in range(0, depth):
        for j in range (0, branch_locations[i]):
            print (" ", end='')

        k = branch_bar[i]
        if (type(k) == tuple):
            k = k[0]
#        print ("b = %d, k = %d" % (branch_locations[i], k), end='')
        print("%s" % (line_type[k]), end='')

def get_thread_count(task):
    thread_list = readSUListFromHead(task.thread_group,
                                     'thread_group',
                                     'struct task_struct');
    return len(thread_list)

def print_task(task, depth, first, options):
    global pid_cnt
    global branch_locations

    pid_cnt = pid_cnt + 1
    thread_str = ""
    if (options.print_thread):
        thread_count = get_thread_count(task)
        if (thread_count > 1):
            if (task.tgid == task.pid):
                thread_str = "---%d*[{%s}]" % (thread_count, task.comm)
            else:
                return 0

    print_branch(depth, first)
    print_str = ("%s%s%s%s " %
           (task.comm,
            "(" + str(task.pid) + ")"
                if options.print_pid else "",
            "[" + task_status_str(task.state) +"]"
                if options.print_state else "",
            thread_str))
    print ("%s" % (print_str), end='')
    if (len(branch_locations) <= depth):
        branch_locations.append(len(print_str))
    else:
        branch_locations[depth] = len(print_str)

    return 1


def print_children(task, depth, options):
    global branch_bar

    depth = depth + 1
    while (len(branch_bar) <= depth):
        branch_bar.append(LineType.LINE_SPACE)

    first = True
    child_list = readSUListFromHead(task.children,
                                    'sibling',
                                    'struct task_struct')
    for idx, child in enumerate(child_list):
        if (idx == len(child_list) - 1):
            branch_bar[depth - 1] = LineType.LINE_LAST
        else:
            branch_bar[depth - 1] = LineType.LINE_BRANCH

        printed = print_task(child, depth, first, options)
        first = False

        if (idx == len(child_list) - 1):
            branch_bar[depth - 1] = LineType.LINE_SPACE
        else:
            branch_bar[depth - 1] = LineType.LINE_VERT

        print_children(child, depth, options)

        if (idx != len(child_list) - 1):
            if (printed > 0):
                print()

def pstree():
    op = OptionParser()
    op.add_option("-p", dest="print_pid", default=0,
                  action="store_true",
                  help="Print process ID")
    op.add_option("-g", dest="print_thread", default=0,
                  action="store_true",
                  help="Print number of threads")
    op.add_option("-s", dest="print_state", default=0,
                  action="store_true",
                  help="Print task state")
    op.add_option("-t", dest="task_id", default=0,
                  type="int", action="store",
                  help="Print specific task and its children")

    (o, args) = op.parse_args()

    print_pstree(o)


if ( __name__ == '__main__'):
    pstree()
