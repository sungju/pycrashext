#!/usr/bin/env/python
# --------------------------------------------------------------------
# (C) Copyright 2018-2019 Red Hat, Inc.
#
# Author: Daniel Sungju Kwon <dkwon@redhat.com>
#
# This command 'pstree' shows process list in tree format
#
#
# Contributors:
# --------------------------------------------------------------------
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
from pykdump.API import *

from LinuxDump.Tasks import Task, TaskTable

import sys
import crashcolor

class LineType(object):
    LINE_SPACE = 0,
    LINE_FIRST = 1,
    LINE_BRANCH = 2,
    LINE_LAST = 3,
    LINE_VERT = 4,
    LINE_SINGLE = 5


ascii_line_type   = ["    ", "-+- ", " |- ", " `- ", " |  ", "--- "]
unicode_line_type = ["    ", "─┬─ ", " ├─ ", " └─ ", " │  ", "─── "]
line_type = unicode_line_type  # default to Unicode
pid_cnt = 0
branch_bar = []
branch_locations = []


def findTaskByPid(task_id):
    init_task = readSymbol("init_task")
    for task in readSUListFromHead(init_task.tasks,
                                   "tasks",
                                   "struct task_struct",
                                   maxel=1000000):
        if (task.pid == task_id or task.tgid == task_id):
            return task

def print_pstree(options):
    global pid_cnt, line_type, branch_bar, branch_locations
    pid_cnt = 0
    branch_bar = []
    branch_locations = []
    line_type = ascii_line_type if options.ascii_mode else unicode_line_type
    init_task = readSymbol("init_task")
    if (options.task_id > 0):
        tt = TaskTable()
        init_task = tt.getByPid(options.task_id)
        if (init_task == None):
            init_task = findTaskByPid(options.task_id)
        if (init_task == None):
            return

    print_task(init_task, 0, True, options)
    print_children(init_task, 0, options)

    print ("\n\nTotal %s tasks printed" % (pid_cnt))
    if (options.print_legend):
        print_state_legend()

# Task state bit flags — stable across all RHEL versions 6-9
TASK_RUNNING        = 0x0000  # 0
TASK_INTERRUPTIBLE  = 0x0001  # 1
TASK_UNINTERRUPTIBLE= 0x0002  # 2
__TASK_STOPPED      = 0x0004  # 4
__TASK_TRACED       = 0x0008  # 8
# exit_state field flags (stored separately from task state in task.exit_state)
# Note: EXIT_ZOMBIE and EXIT_DEAD values swapped between kernel generations:
#   RHEL 6/7 (2.6.32/3.10): EXIT_ZOMBIE=0x10, EXIT_DEAD=0x20, TASK_DEAD=0x40
#   RHEL 8/9 (4.18/5.14+):  EXIT_DEAD=0x10,  EXIT_ZOMBIE=0x20, TASK_DEAD=0x80
# We use RHEL8/9 values for EXIT_DEAD/EXIT_ZOMBIE (correct zombie vs dead on modern kernels).
# On RHEL6/7 the zombie/dead labels may be swapped cosmetically, but both are non-running.
EXIT_DEAD           = 0x0010  # EXIT_DEAD on RHEL8/9, EXIT_ZOMBIE on RHEL6/7
EXIT_ZOMBIE         = 0x0020  # EXIT_ZOMBIE on RHEL8/9, EXIT_DEAD on RHEL6/7
TASK_DEAD_MASK      = 0x00C0  # covers TASK_DEAD=0x40 (RHEL6/7) and 0x80 (RHEL8/9)
# Additional state flags
TASK_WAKEKILL       = 0x0100
TASK_NOLOAD         = 0x0400
TASK_NEW            = 0x0800

def task_state_color(state):
    # Handle string states (older pykdump may return symbolic names)
    if isinstance(state, str):
        s = state.split("|")[0].strip()
        return {
            "TASK_RUNNING":        crashcolor.BLUE,
            "TASK_INTERRUPTIBLE":  crashcolor.RESET,
            "TASK_UNINTERRUPTIBLE":crashcolor.RED,
            "TASK_STOPPED":        crashcolor.CYAN,
            "__TASK_STOPPED":      crashcolor.CYAN,
            "__TASK_TRACED":       crashcolor.MAGENTA,
            "TASK_ZOMBIE":         crashcolor.YELLOW,
            "EXIT_ZOMBIE":         crashcolor.YELLOW,
            "TASK_DEAD":           crashcolor.LIGHTRED,
            "EXIT_DEAD":           crashcolor.LIGHTRED,
        }.get(s, crashcolor.RESET)

    # Bitmask priority for integer states (covers composite states and all kernel versions)
    state = int(state)
    if state & (EXIT_ZOMBIE | EXIT_DEAD | TASK_DEAD_MASK):
        # Zombie takes priority over dead
        if state & EXIT_ZOMBIE:
            return crashcolor.YELLOW
        return crashcolor.LIGHTRED
    if state & __TASK_STOPPED:
        return crashcolor.CYAN
    if state & __TASK_TRACED:
        return crashcolor.MAGENTA
    if state & TASK_UNINTERRUPTIBLE:
        return crashcolor.RED
    if state & TASK_INTERRUPTIBLE:
        return crashcolor.RESET
    if state == TASK_RUNNING:
        return crashcolor.BLUE
    return crashcolor.RESET


def task_state_str(state):
    if isinstance(state, str):
        s = state.split("|")[0].strip()
        return {
            "TASK_RUNNING":        "RU",
            "TASK_INTERRUPTIBLE":  "IN",
            "TASK_UNINTERRUPTIBLE":"UN",
            "TASK_STOPPED":        "ST",
            "__TASK_STOPPED":      "ST",
            "__TASK_TRACED":       "TR",
            "TASK_ZOMBIE":         "ZO",
            "EXIT_ZOMBIE":         "ZO",
            "TASK_DEAD":           "DE",
            "EXIT_DEAD":           "DE",
        }.get(s, "??")

    state = int(state)
    if state & EXIT_ZOMBIE:
        return "ZO"
    if state & (EXIT_DEAD | TASK_DEAD_MASK):
        return "DE"
    if state & __TASK_STOPPED:
        return "ST"
    if state & __TASK_TRACED:
        return "TR"
    if state & TASK_UNINTERRUPTIBLE:
        return "UN"
    if state & TASK_INTERRUPTIBLE:
        return "IN"
    if state == TASK_RUNNING:
        return "RU"
    return "??"


def print_branch(depth, first):
    global branch_locations
    global branch_bar

    if (first and depth > 0):
        # first==2 means only child — use straight connector, not branching ─┬─
        connector_idx = 5 if (first == 2) else 1
        print ("%s" % (line_type[connector_idx],), end='')
        return

    for i in range(0, depth):
        for j in range (0, branch_locations[i]):
            print (" ", end='')

        k = branch_bar[i]
        if (type(k) == tuple):
            k = k[0]
#        print ("b = %d, k = %d" % (branch_locations[i], k), end='')
        print("%s" % (line_type[k],), end='')


def print_threads(task, depth, options):
    global branch_bar, branch_locations, pid_cnt

    if task.tgid != task.pid:
        return  # only for group leader

    thread_list = readSUListFromHead(task.thread_group,
                                     'thread_group',
                                     'struct task_struct',
                                     maxel=1000000)
    threads = [t for t in thread_list if t.pid != task.pid]
    if not threads:
        return

    depth = depth + 1
    while len(branch_bar) <= depth:
        branch_bar.append(LineType.LINE_SPACE)

    for idx, thread in enumerate(threads):
        pid_cnt += 1

        if idx == len(threads) - 1:
            branch_bar[depth - 1] = LineType.LINE_LAST
        else:
            branch_bar[depth - 1] = LineType.LINE_BRANCH

        # threads always appear on new lines — always use full alignment (first=False)
        print_branch(depth, False)

        thread_comm = thread.comm if thread.comm != 0 else ""
        thread_state = get_task_state(thread)
        thread_color = task_state_color(thread_state)
        if thread_color != crashcolor.RESET:
            crashcolor.set_color(thread_color)

        pid_str = "(%d)" % thread.pid if options.print_pid else ""
        state_str = "[%s]" % task_state_str(thread_state) if options.print_state else ""
        print_str = "{%s}%s%s " % (thread_comm, pid_str, state_str)
        print(print_str, end='')

        if thread_color != crashcolor.RESET:
            crashcolor.set_color(crashcolor.RESET)

        if len(branch_locations) <= depth:
            branch_locations.append(len(print_str))
        else:
            branch_locations[depth] = len(print_str)

        if idx != len(threads) - 1:
            branch_bar[depth - 1] = LineType.LINE_VERT
            print()

    branch_bar[depth - 1] = LineType.LINE_SPACE


def get_thread_count(task):
    thread_list = readSUListFromHead(task.thread_group,
                                     'thread_group',
                                     'struct task_struct',
                                     maxel=1000000);
    return len(thread_list)


def is_kernel_thread(task):
    try:
        return task.mm == 0
    except:
        return False


def get_task_state(task):
    state = 0
    if member_offset("struct task_struct", "__state") >= 0:
        state = int(task.__state)
    elif member_offset("struct task_struct", "state") >= 0:
        state = int(task.state)
    if member_offset("struct task_struct", "exit_state") >= 0:
        try:
            state |= int(task.exit_state)
        except:
            pass
    return state


def print_task(task, depth, first, options):
    global pid_cnt
    global branch_locations

    if (task == None):
        return

    pid_cnt = pid_cnt + 1
    thread_str = ""
    if options.print_thread and not getattr(options, 'show_threads', False):
        thread_count = get_thread_count(task)
        if thread_count > 1:
            if task.tgid == task.pid:
                thread_str = "{%d}" % thread_count
            else:
                return 0  # hide non-main threads when -g without -T

    print_branch(depth, first)

    comm_str = ""
    if (task.comm != 0):
        comm_str = task.comm
    if is_kernel_thread(task):
        comm_str = "[%s]" % comm_str

    task_state = get_task_state(task)
    task_color = task_state_color(task_state)
    if task_color != crashcolor.RESET:
        crashcolor.set_color(task_color)

    if member_offset("struct kuid_t", "val") >= 0:
        task_uid = task.loginuid.val
    else:
        task_uid = task.loginuid

    if task_uid == 0xffffffff:
        task_uid = 0
    print_str = ("%s%s%s%s%s " %
           (comm_str,
            "(" + str(task.pid) + ")"
                if options.print_pid else "",
            "[" + task_state_str(get_task_state(task)) +"]"
                if options.print_state else "",
            "{" + str(task_uid) + "}"
                if options.print_uid else "",
            thread_str))
    print ("%s" % (print_str), end='')
    if task_color != crashcolor.RESET:
        crashcolor.set_color(crashcolor.RESET)
    if (len(branch_locations) <= depth):
        branch_locations.append(len(print_str))
    else:
        branch_locations[depth] = len(print_str)

    return 1


def task_has_children(task):
    # An empty list_head has next == &self (points to itself).
    # Using pointer comparison avoids readSUListFromHead and its maxel warnings.
    try:
        return task.children.next != Addr(task.children)
    except:
        return False


def task_has_threads(task):
    # An empty thread_group list_head has next == &self (only the task itself).
    try:
        if task.tgid != task.pid:
            return False
        return task.thread_group.next != Addr(task.thread_group)
    except:
        return False


def get_compact_groups(child_list, options):
    if not getattr(options, 'compact_mode', True) or not child_list:
        return [(1, c) for c in child_list]
    groups = []
    i = 0
    while i < len(child_list):
        comm = child_list[i].comm
        if not task_has_children(child_list[i]):
            # count consecutive same-named leaves
            j = i + 1
            while j < len(child_list):
                if child_list[j].comm != comm:
                    break
                if task_has_children(child_list[j]):
                    break
                j += 1
            if j - i > 1:
                groups.append((j - i, child_list[i]))
                i = j
                continue
        groups.append((1, child_list[i]))
        i += 1
    return groups


def print_children(task, depth, options):
    global branch_bar, branch_locations, pid_cnt

    if (task == None):
        return

    depth = depth + 1
    while (len(branch_bar) <= depth):
        branch_bar.append(LineType.LINE_SPACE)

    child_list = readSUListFromHead(task.children,
                                    'sibling',
                                    'struct task_struct',
                                    maxel=1000000)
    groups = get_compact_groups(child_list, options)

    # Build unified item list: task's own threads first, then child processes.
    # Threads appear as {name} siblings before child processes.
    all_items = []
    if getattr(options, 'show_threads', False) and task.tgid == task.pid:
        try:
            thread_list = readSUListFromHead(task.thread_group,
                                             'thread_group',
                                             'struct task_struct',
                                             maxel=1000000)
            for t in thread_list:
                if t.pid != task.pid:
                    all_items.append(('thread', 1, t))
        except:
            pass
    for count, child in groups:
        all_items.append(('proc', count, child))

    if not all_items:
        return

    first = 2 if len(all_items) == 1 else True
    for idx, item in enumerate(all_items):
        if idx == len(all_items) - 1:
            branch_bar[depth - 1] = LineType.LINE_LAST
        else:
            branch_bar[depth - 1] = LineType.LINE_BRANCH

        kind = item[0]
        count = item[1]
        obj = item[2]

        if kind == 'thread':
            pid_cnt += 1
            print_branch(depth, first)
            first = False

            thread_comm = obj.comm if obj.comm != 0 else ""
            thread_state = get_task_state(obj)
            thread_color = task_state_color(thread_state)
            if thread_color != crashcolor.RESET:
                crashcolor.set_color(thread_color)
            pid_str = "(%d)" % obj.pid if options.print_pid else ""
            state_str = "[%s]" % task_state_str(thread_state) if options.print_state else ""
            print_str = "{%s}%s%s " % (thread_comm, pid_str, state_str)
            print(print_str, end='')
            if thread_color != crashcolor.RESET:
                crashcolor.set_color(crashcolor.RESET)
            if len(branch_locations) <= depth:
                branch_locations.append(len(print_str))
            else:
                branch_locations[depth] = len(print_str)
            printed = 1

        else:  # 'proc'
            child = obj
            if count > 1:
                print_branch(depth, first)
                first = False
                cstate = get_task_state(child)
                ccolor = task_state_color(cstate)
                if ccolor != crashcolor.RESET:
                    crashcolor.set_color(ccolor)
                ccomm = child.comm if child.comm != 0 else ""
                if is_kernel_thread(child):
                    ccomm = "[%s]" % ccomm
                compact_str = "%d*[%s] " % (count, ccomm)
                print(compact_str, end='')
                if ccolor != crashcolor.RESET:
                    crashcolor.set_color(crashcolor.RESET)
                if len(branch_locations) <= depth:
                    branch_locations.append(len(compact_str))
                else:
                    branch_locations[depth] = len(compact_str)
                pid_cnt += count
                printed = 1
            else:
                printed = print_task(child, depth, first, options)
                first = False

        if idx == len(all_items) - 1:
            branch_bar[depth - 1] = LineType.LINE_SPACE
        else:
            branch_bar[depth - 1] = LineType.LINE_VERT

        if kind == 'proc' and count == 1:
            print_children(child, depth, options)

        if idx != len(all_items) - 1:
            if printed > 0:
                print()

def print_state_legend():
    print("\nState colors:")
    states = [
        (crashcolor.BLUE,     "RU", "Running"),
        (crashcolor.RESET,    "IN", "Interruptible sleep"),
        (crashcolor.RED,      "UN", "Uninterruptible sleep"),
        (crashcolor.CYAN,     "ST", "Stopped"),
        (crashcolor.MAGENTA,  "TR", "Traced"),
        (crashcolor.YELLOW,   "ZO", "Zombie"),
        (crashcolor.LIGHTRED, "DE", "Dead"),
    ]
    for color, code, label in states:
        crashcolor.set_color(color)
        print("  [%s] %s" % (code, label), end='')
        crashcolor.set_color(crashcolor.RESET)
        print()

def pstree():
    op = OptionParser()
    op.add_option("-p", dest="print_pid", default=0,
                  action="store_true",
                  help="Print process ID")
    op.add_option("-u", dest="print_uid", default=0,
                  action="store_true",
                  help="Print User ID")
    op.add_option("-g", dest="print_thread", default=0,
                  action="store_true",
                  help="Print number of threads")
    op.add_option("-s", dest="print_state", default=0,
                  action="store_true",
                  help="Print task state")
    op.add_option("-t", dest="task_id", default=0,
                  type="int", action="store",
                  help="Print specific task and its children")
    op.add_option("-A", dest="ascii_mode", default=False,
                  action="store_true",
                  help="Use ASCII characters for tree (default: Unicode)")
    op.add_option("-l", dest="print_legend", default=False,
                  action="store_true",
                  help="Print state color legend")
    op.add_option("-T", dest="show_threads", default=False,
                  action="store_true",
                  help="Show threads as children with {name} notation")
    op.add_option("-c", dest="compact_mode", default=True,
                  action="store_false",
                  help="Disable compact mode (compact identical leaf processes by default)")

    (o, args) = op.parse_args()

    sys.setrecursionlimit(10**6)

    print_pstree(o)


if ( __name__ == '__main__'):
    pstree()
