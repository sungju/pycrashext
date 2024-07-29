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
    LINE_VERT = 4


line_type = ["    ", "-+- ", " |- ", " `- ", " |  "]
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
    global pid_cnt
    pid_cnt = 0
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

TASK_RUNNING = 0
TASK_INTERRUPTIBLE = 1
TASK_UNINTERRUPTIBLE = 2
__TASK_STOPPED = 4
__TASK_TRACED = 8
EXIT_ZOMBIE = 16
EXIT_DEAD = 32
TASK_DEAD = 64

def task_state_color(state):
    if isinstance(state, int):
        state = state & 0x7f
    elif "|" in state:
        state = state[:state.find("|")]

    try:
        return {
            TASK_RUNNING : crashcolor.BLUE,
            TASK_INTERRUPTIBLE : crashcolor.RESET,
            TASK_UNINTERRUPTIBLE : crashcolor.RED,
            __TASK_STOPPED : crashcolor.CYAN,
            __TASK_TRACED : crashcolor.MAGENTA,
            EXIT_ZOMBIE : crashcolor.YELLOW,
            EXIT_DEAD : crashcolor.LIGHTRED,
            TASK_DEAD : crashcolor.LIGHTRED,
            "TASK_RUNNING" : crashcolor.BLUE,
            "TASK_INTERRUPTIBLE" : crashcolor.RESET,
            "TASK_UNINTERRUPTIBLE" : crashcolor.RED,
            "TASK_STOPPED" : crashcolor.CYAN,
            "__TASK_STOPPED" : crashcolor.CYAN,
            "__TASK_TRACED" : crashcolor.MAGENTA,
            "TASK_ZOMBIE" : crashcolor.YELLOW,
            "TASK_DEAD" : crashcolor.LIGHTRED,
        }[state]
    except:
        return crashcolor.RESET


def task_state_str(state):
    if isinstance(state, int):
        state = state & 0x7f
    elif "|" in state:
        state = state[:state.find("|")]

    try:
        return {
            TASK_RUNNING: "RU",
            TASK_INTERRUPTIBLE: "IN",
            TASK_UNINTERRUPTIBLE: "UN",
            __TASK_STOPPED: "ST",
            __TASK_TRACED: "TR",
            EXIT_ZOMBIE: "ZO",
            EXIT_DEAD: "DE",
            TASK_DEAD: "DE",
            "TASK_RUNNING" : "RU",
            "TASK_INTERRUPTIBLE" : "IN",
            "TASK_UNINTERRUPTIBLE" : "UN",
            "TASK_STOPPED" : "ST",
            "__TASK_STOPPED" : "ST",
            "__TASK_TRACED" : "TR",
            "TASK_ZOMBIE" : "ZO",
            "TASK_DEAD" : "DE",
        }[state]
    except:
        return "??"


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
                                     'struct task_struct',
                                     maxel=1000000);
    return len(thread_list)


def get_task_state(task):
    if member_offset("struct task_struct", "state") >= 0:
        return task.state

    if member_offset("struct task_struct", "__state") >= 0:
        return task.__state

    return 0


def print_task(task, depth, first, options):
    global pid_cnt
    global branch_locations

    if (task == None):
        return

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

    comm_str = ""
    if (task.comm != 0):
        comm_str = task.comm

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


def print_children(task, depth, options):
    global branch_bar

    if (task == None):
        return

    depth = depth + 1
    while (len(branch_bar) <= depth):
        branch_bar.append(LineType.LINE_SPACE)

    first = True
    child_list = readSUListFromHead(task.children,
                                    'sibling',
                                    'struct task_struct',
                                    maxel=1000000)
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

    (o, args) = op.parse_args()

    sys.setrecursionlimit(10**6)

    print_pstree(o)


if ( __name__ == '__main__'):
    pstree()
